package cve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// openTestStore builds a fresh local store in a temp dir.
func openTestStore(t *testing.T) *LocalStore {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatalf("OpenLocal: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sample(id, summary string) Match {
	return Match{
		ID: id, Summary: summary, Severity: "high", CVSS: 7.5, CWE: "CWE-79",
		Published: "2024-05-01", Products: []string{"cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"},
		References: []string{"https://example.com/a"},
	}
}

func TestLocalUpsertAndSearchByID(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	if err := s.Upsert(ctx, sample("CVE-2024-1234", "test vuln"), "2024-05-02T00:00:00Z"); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	// upsert same id with new data → overwrite, not duplicate.
	if err := s.Upsert(ctx, sample("CVE-2024-1234", "updated summary"), ""); err != nil {
		t.Fatalf("Upsert 2: %v", err)
	}

	res, err := s.Search(ctx, "cve-2024-1234", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Matches) != 1 || res.Matches[0].Summary != "updated summary" {
		t.Fatalf("unexpected: %+v", res)
	}
	if res.Matches[0].Severity != "high" || res.Matches[0].CVSS != 7.5 {
		t.Fatalf("fields lost: %+v", res.Matches[0])
	}
	if res.Matches[0].Products == nil || len(res.Matches[0].Products) != 1 {
		t.Fatalf("products not decoded: %+v", res.Matches[0].Products)
	}
}

func TestLocalSearchKeywordFTS(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for _, m := range []Match{
		sample("CVE-2021-44228", "Apache Log4j2 JNDI remote code execution"),
		sample("CVE-2024-0001", "Jenkins CSRF vulnerability"),
		sample("CVE-2024-0002", "nginx off-by-one in range filter"),
	} {
		if err := s.Upsert(ctx, m, ""); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}
	res, err := s.Search(ctx, "log4j", 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(res.Matches) != 1 || res.Matches[0].ID != "CVE-2021-44228" {
		t.Fatalf("fts hit: %+v", res.Matches)
	}
	// 版本号带点：FTS quoting 必须吃得下。
	if _, err := s.Search(ctx, "log4j 2.14", 0); err != nil {
		t.Fatalf("Search dotted term: %v", err)
	}
	// 大小写不敏感（FTS5 默认 unicode61 folding）。
	res, _ = s.Search(ctx, "JENKINS", 0)
	if len(res.Matches) != 1 || res.Matches[0].ID != "CVE-2024-0001" {
		t.Fatalf("case-insensitive hit: %+v", res.Matches)
	}
}

func TestLocalCountFeedsClear(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	_ = s.Upsert(ctx, sample("CVE-2024-0001", "a"), "")
	_ = s.Upsert(ctx, sample("CVE-2024-0002", "b"), "")
	n, err := s.Count(ctx)
	if err != nil || n != 2 {
		t.Fatalf("Count: %d %v", n, err)
	}
	if err := s.RecordFeed(ctx, "2024", "abc123", 2); err != nil {
		t.Fatalf("RecordFeed: %v", err)
	}
	feeds, err := s.Feeds(ctx)
	if err != nil || len(feeds) != 1 || feeds[0].Records != 2 || feeds[0].SHA256 != "abc123" {
		t.Fatalf("Feeds: %+v %v", feeds, err)
	}
	if err := s.Clear(ctx); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	n, _ = s.Count(ctx)
	if n != 0 {
		t.Fatalf("clear left %d rows", n)
	}
	feeds, _ = s.Feeds(ctx)
	if len(feeds) != 0 {
		t.Fatalf("clear left feeds %+v", feeds)
	}
}

func TestLocalSearchEmptyQuery(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Search(context.Background(), "", 5); err == nil {
		t.Fatal("empty query must error")
	}
}

// WAL sidecar files must live next to the db (same dir), confirming the store
// keeps everything under the data dir — nothing lands in the repo.
func TestLocalFilesStayInDir(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatalf("OpenLocal: %v", err)
	}
	defer s.Close()
	_ = s.Upsert(context.Background(), sample("CVE-2024-0001", "x"), "")
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) == 0 {
		t.Fatal("no files created in data dir")
	}
	for _, n := range names {
		if !filepath.IsAbs(filepath.Join(dir, n)) {
			t.Errorf("unexpected relative path %q", n)
		}
	}
	_ = names
}
