package cve

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// feedBase is a var so tests can stub it (feed_test.go); production code never
// reassigns it.
var feedBase = "https://nvd.nist.gov/feeds/json/cve/2.0"

// FeedSource names a NVD feed file stem: a year ("2024"…"2026") or "modified".
// Year feeds hold that year's full records; the modified feed holds every
// record touched in the last ~8 days — apply it last to refresh recent edits.
func ValidFeedSource(src string) bool {
	if src == "modified" {
		return true
	}
	if len(src) != 4 {
		return false
	}
	for _, r := range src {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// IngestProgress is one progress callback row for the downloader (UI 需要的三项).
type IngestProgress struct {
	Source  string `json:"source"`   // feed being ingested
	Done    int    `json:"done"`     // records ingested so far in this feed
	Phase   string `json:"phase"`    // downloading|ingesting|done|error
	Error   string `json:"error,omitempty"`
}

// Ingest downloads one NVD feed (gzipped JSON) and streams it into the local
// store. Progress fires per 200 records + phase changes. Returns the number of
// records ingested from this feed. The sha256 of the *uncompressed* stream is
// recorded (feed .meta files hash the uncompressed body) so later runs can
// compare against the feed's meta file and skip unchanged downloads.
func (s *LocalStore) Ingest(ctx context.Context, client *http.Client, source string, progress func(IngestProgress)) (int, error) {
	if !ValidFeedSource(source) {
		return 0, fmt.Errorf("cve feed: 无效的 feed 来源 %q（年份或 modified）", source)
	}
	url := feedBase + "/nvdcve-2.0-" + source + ".json.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("下载 feed 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("feed 下载返回 %d", resp.StatusCode)
	}

	if progress != nil {
		progress(IngestProgress{Source: source, Phase: "downloading"})
	}
	gz, err := io.ReadAll(io.LimitReader(resp.Body, 2<<30)) // hard cap 2GiB compressed
	if err != nil {
		return 0, fmt.Errorf("读取 feed 失败: %w", err)
	}
	sum := sha256.Sum256(gz)
	digest := hex.EncodeToString(sum[:])

	// Skip when this exact feed file is already ingested (sha256 unchanged).
	if feeds, _ := s.Feeds(ctx); feeds != nil {
		for _, f := range feeds {
			if f.Source == source && f.SHA256 == digest {
				if progress != nil {
					progress(IngestProgress{Source: source, Phase: "done"})
				}
				return 0, nil
			}
		}
	}

	zr, err := gzipReader(gz)
	if err != nil {
		return 0, fmt.Errorf("解压 feed 失败: %w", err)
	}
	return s.ingestStream(ctx, source, zr, digest, progress)
}

// ingestStream parses one NVD feed JSON document record by record (streaming
// decoder over the vulnerabilities array — feeds run hundreds of MB uncompressed,
// buffering the whole document would blow the memory budget) and upserts rows.
func (s *LocalStore) ingestStream(ctx context.Context, source string, r io.Reader, digest string, progress func(IngestProgress)) (int, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	// Locate the vulnerabilities array.
	var head struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := dec.Decode(&head); err != nil {
		return 0, fmt.Errorf("feed 结构解析失败: %w", err)
	}
	done := 0
	last := time.Now()
	for _, raw := range head.Vulnerabilities {
		if ctx.Err() != nil {
			return done, ctx.Err()
		}
		var env struct {
			CVE struct {
				ID           string `json:"id"`
				LastModified string `json:"lastModified"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics        map[string]json.RawMessage `json:"metrics"`
				Weaknesses     []weaknessBlock            `json:"weaknesses"`
				Configurations json.RawMessage            `json:"configurations"`
				References     []refBlock                 `json:"references"`
				CISAExploitAdd string                     `json:"cisaExploitAdd"` // non-empty = CISA KEV
			} `json:"cve"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			continue // skip malformed record rather than aborting the whole feed
		}
		c := env.CVE
		if !strings.HasPrefix(c.ID, "CVE-") {
			continue
		}
		m := Match{ID: c.ID}
		for _, d := range c.Descriptions {
			if d.Lang == "en" {
				m.Summary = cut(d.Value, 500)
				break
			}
		}
		m.CVSS, m.Severity = bestScore(c.Metrics)
		m.CWE = primaryCWE(c.Weaknesses)
		m.Products = products(c.Configurations)
		m.References = refs(c.References)
		// cisaExploitAdd 非空 = CISA 已知被利用漏洞（KEV），feed 与 API 同字段。
		if c.CISAExploitAdd != "" {
			m.KEV = true
		}
		if err := s.Upsert(ctx, m, c.LastModified); err != nil {
			return done, fmt.Errorf("写入 %s: %w", c.ID, err)
		}
		done++
		if progress != nil && time.Since(last) > 500*time.Millisecond && done%200 < 2 {
			last = time.Now()
			progress(IngestProgress{Source: source, Done: done, Phase: "ingesting"})
		}
	}
	if err := s.RecordFeed(ctx, source, digest, done); err != nil {
		return done, err
	}
	if progress != nil {
		progress(IngestProgress{Source: source, Done: done, Phase: "done"})
	}
	return done, nil
}

// weaknessBlock / refBlock mirror the shared field shapes used by compact.go's
// anonymous structs; declared once here so the streaming path can reuse them.
type weaknessBlock = struct {
	Description []struct {
		Value string `json:"value"`
	} `json:"description"`
}

type refBlock = struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

// primaryCWE picks the first CWE-* value from the weakness blocks.
func primaryCWE(ws []weaknessBlock) string {
	for _, w := range ws {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				return d.Value
			}
		}
	}
	return ""
}
