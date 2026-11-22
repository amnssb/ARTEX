// Package cve 已有在线检索（NVD API）。本文件是本地漏洞库：
// data/cve/local.sqlite 存下载好的全量 CVE（同 NVD feed 的压缩形态），供纯内网/
// 离线部署的 cve_search 查询。数据文件在运行数据目录下（/data/ 已在 .gitignore），
// 永不进仓库；删掉即回到纯在线模式。
//
// 调用示例：
//
//	store, err := cve.OpenLocal(filepath.Join(dataDir, "cve"))
//	defer store.Close()
//	res, n := store.Search("log4j", 5)      // 关键词/编号查询
//	n, err = store.Ingest(ctx, r, progress) // 流式导入 NVD feed JSON reader
package cve

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, same as traffic's index store
)

// LocalStore owns <dataDir>/local.sqlite. Safe for concurrent use.
type LocalStore struct {
	db *sql.DB
}

// OpenLocal opens (and initializes) the local CVE store under dir. dir is
// created on demand so callers can pass the intended location directly.
func OpenLocal(dir string) (*LocalStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dir+"/local.sqlite?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	s := &LocalStore{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// init creates the schema on a fresh file; existing files are untouched
// (CREATE TABLE IF NOT EXISTS), so upgrades only need new columns/migrations.
func (s *LocalStore) init() error {
	for _, p := range []string{
		`CREATE TABLE IF NOT EXISTS cves (
			id          TEXT PRIMARY KEY,          -- CVE-YYYY-NNNN
			summary     TEXT NOT NULL,
			severity    TEXT NOT NULL,
			cvss        REAL NOT NULL,
			cwe         TEXT,
			published   TEXT,
			products    TEXT,                      -- JSON array of CPE criteria
			"references" TEXT,                     -- JSON array of URLs (quoted: REFERENCES is an SQL keyword)
			kev         INTEGER NOT NULL DEFAULT 0,
			last_modified TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published DESC)`,
		`CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
			id, summary, content='',               -- standalone index; triggers keep it in sync
		)`,
		// Triggers keep the standalone FTS index in sync; the JOIN keys on the
		// cves rowid stored in fts rowid (same insert order, 1:1 rows).
		`CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
			INSERT INTO cves_fts(rowid, id, summary) VALUES (new.rowid, new.id, new.summary);
		END`,
		`CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE ON cves BEGIN
			INSERT INTO cves_fts(cves_fts, rowid, id, summary) VALUES ('delete', old.rowid, old.id, old.summary);
			INSERT INTO cves_fts(rowid, id, summary) VALUES (new.rowid, new.id, new.summary);
		END`,
		`CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
			INSERT INTO cves_fts(cves_fts, rowid, id, summary) VALUES ('delete', old.rowid, old.id, old.summary);
		END`,
		// meta: one row per ingest source (year feed / modified feed), so the UI can
		// show freshness and the updater can skip unchanged files (by sha256).
		`CREATE TABLE IF NOT EXISTS cve_feeds (
			source      TEXT PRIMARY KEY,          -- "2024" | "2025" | "modified"
			sha256      TEXT,
			records     INTEGER NOT NULL,
			ingested_at TEXT NOT NULL              -- RFC3339
		)`,
	} {
		if _, err := s.db.Exec(p); err != nil {
			return fmt.Errorf("cve local schema: %w", err)
		}
	}
	return nil
}

// Close releases the database handle.
func (s *LocalStore) Close() error { return s.db.Close() }

// cveRow is the storage shape of one record (same fields as Match).
type cveRow struct {
	ID           string
	Summary      string
	Severity     string
	CVSS         float64
	CWE          string
	Published    string
	Products     string // JSON array
	References   string // JSON array
	KEV          bool
	LastModified string
}

// rowToMatch decodes a row into the public Match shape.
func rowToMatch(r cveRow) Match {
	m := Match{
		ID: r.ID, Summary: cut(r.Summary, 500), Severity: r.Severity,
		CVSS: r.CVSS, CWE: r.CWE, Published: r.Published, KEV: r.KEV,
	}
	_ = json.Unmarshal([]byte(r.Products), &m.Products)
	_ = json.Unmarshal([]byte(r.References), &m.References)
	return m
}

// Upsert ingests one compact match (idempotent on id). Called by the downloader
// per record while streaming a feed.
func (s *LocalStore) Upsert(ctx context.Context, m Match, lastModified string) error {
	products, _ := json.Marshal(m.Products)
	refs, _ := json.Marshal(m.References)
	kev := 0
	if m.KEV {
		kev = 1
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO cves(id, summary, severity, cvss, cwe, published, products, "references", kev, last_modified)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT(id) DO UPDATE SET
	summary=$2, severity=$3, cvss=$4, cwe=$5, published=$6, products=$7,
	"references"=$8, kev=$9, last_modified=$10`,
		m.ID, m.Summary, m.Severity, m.CVSS, m.CWE, m.Published,
		string(products), string(refs), kev, lastModified)
	return err
}

// localNote replaces the online note when results come from the local store:
// same red line (a hit is a lead, not a finding), plus the data's provenance.
const localNote = "检索结果来自本地 CVE 库（NVD feed 快照，可能滞后于最新披露），只是线索（inferred）：命中不代表已利用成功，禁止直接当作 finding 上报——必须实际触发并拿到可复现证据后走 report_finding，否则 record_fact(confidence=inferred) 交规划者。"

// Search queries the local store: exact CVE id (case-insensitive prefix match on
// the id) or FTS keyword search, newest published first. limit<=0 → 5, cap 20.
func (s *LocalStore) Search(ctx context.Context, query string, limit int) (*Result, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("cve local: query 不能为空")
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	out := &Result{Query: query, Note: localNote}
	if IsCVEID(query) {
		rows, err := s.db.QueryContext(ctx, `
SELECT id, summary, severity, cvss, cwe, published, products, "references", kev
FROM cves WHERE id = $1 LIMIT $2`, strings.ToUpper(query), limit)
		if err != nil {
			return nil, err
		}
		matches, err := scanMatches(rows)
		if err != nil {
			return nil, err
		}
		out.Matches = matches
		out.Total = len(matches)
		return out, nil
	}
	// Keyword: FTS5 match. Query quoting: wrap each term in double quotes so
	// hyphens/dots in product names don't act as FTS operators.
	fts := strings.Join(strings.Fields(query), " ")
	rows, err := s.db.QueryContext(ctx, `
SELECT c.id, c.summary, c.severity, c.cvss, c.cwe, c.published, c.products, c."references", c.kev
FROM cves_fts f JOIN cves c ON c.rowid = f.rowid
WHERE cves_fts MATCH $1
ORDER BY c.published DESC, c.cvss DESC LIMIT $2`, ftsToQuery(fts), limit)
	if err != nil {
		return nil, err
	}
	matches, err := scanMatches(rows)
	if err != nil {
		return nil, err
	}
	out.Matches = matches
	// total is the filtered count only when cheap; return page size as a floor.
	out.Total = len(matches)
	return out, nil
}

// ftsToQuery quotes each term and turns it into a prefix query ("log4j" →
// `"log4j"*`): version tokens like `Log4j2`/`2.14.1` tokenize as whole
// tokens, so a bare term would never match a longer product-version string.
// Prefix matching on every term is what a product-keyword search expects.
func ftsToQuery(fts string) string {
	fields := strings.Fields(fts)
	for i, f := range fields {
		fields[i] = `"` + strings.ReplaceAll(f, `"`, `""`) + `"*`
	}
	return strings.Join(fields, " ")
}

func scanMatches(rows *sql.Rows) ([]Match, error) {
	defer rows.Close()
	var out []Match
	for rows.Next() {
		var r cveRow
		if err := rows.Scan(&r.ID, &r.Summary, &r.Severity, &r.CVSS, &r.CWE,
			&r.Published, &r.Products, &r.References, &r.KEV); err != nil {
			return nil, err
		}
		out = append(out, rowToMatch(r))
	}
	return out, rows.Err()
}

// Count returns the total number of stored records (for the UI status card).
func (s *LocalStore) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM cves`).Scan(&n)
	return n, err
}

// FeedInfo is one ingested feed's freshness record (for the UI status card).
type FeedInfo struct {
	Source     string `json:"source"`
	Records    int    `json:"records"`
	IngestedAt string `json:"ingested_at"`
	SHA256     string `json:"sha256,omitempty"`
}

// Feeds lists what has been ingested, newest first.
func (s *LocalStore) Feeds(ctx context.Context) ([]FeedInfo, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT source, records, ingested_at, COALESCE(sha256,'') FROM cve_feeds ORDER BY ingested_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FeedInfo
	for rows.Next() {
		var f FeedInfo
		if err := rows.Scan(&f.Source, &f.Records, &f.IngestedAt, &f.SHA256); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RecordFeed marks one feed ingest complete (source, digest, record count).
func (s *LocalStore) RecordFeed(ctx context.Context, source, sha string, records int) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO cve_feeds(source, sha256, records, ingested_at) VALUES ($1,$2,$3,$4)
ON CONFLICT(source) DO UPDATE SET sha256=$2, records=$3, ingested_at=$4`,
		source, sha, records, time.Now().UTC().Format(time.RFC3339))
	return err
}

// Clear wipes every stored record and feed marker (回到纯在线模式).
func (s *LocalStore) Clear(ctx context.Context) error {
	for _, p := range []string{`DELETE FROM cves`, `DELETE FROM cve_feeds`} {
		if _, err := s.db.ExecContext(ctx, p); err != nil {
			return err
		}
	}
	return nil
}
