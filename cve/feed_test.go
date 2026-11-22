package cve

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// feedStub serves a gzipped NVD feed for one source at the real URL path.
func feedStub(t *testing.T, source, body string) *httptest.Server {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(body))
	_ = zw.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/nvdcve-2.0-"+source+".json.gz") {
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write(buf.Bytes())
	}))
	t.Cleanup(srv.Close)
	return srv
}

func stubFeedBase(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := feedBase
	feedBase = srv.URL
	t.Cleanup(func() { feedBase = old })
}

func feedBody(t *testing.T, records map[string]string) string {
	t.Helper()
	vulns := make([]string, 0, len(records))
	for id, summary := range records {
		b, _ := json.Marshal(map[string]any{
			"cve": map[string]any{
				"id":           id,
				"lastModified": "2024-06-01T00:00:00.000",
				"descriptions": []map[string]string{{"lang": "en", "value": summary}},
				"metrics": map[string]any{
					"cvssMetricV31": []map[string]any{{"cvssData": map[string]any{"baseScore": 9.8, "baseSeverity": "CRITICAL"}}},
				},
				"weaknesses": []map[string]any{{"description": []map[string]string{{"lang": "en", "value": "CWE-89"}}}},
				"configurations": []map[string]any{{"nodes": []map[string]any{{
					"cpeMatch": []map[string]any{{"criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*"}},
				}}}},
				"references": []map[string]any{{"url": "https://example.com/p", "tags": []string{"Patch"}}},
				"cisaExploitAdd": "2024-06-02",
			},
		})
		vulns = append(vulns, string(b))
	}
	return `{"resultsPerPage":` + itoa(len(records)) + `,"vulnerabilities":[` + strings.Join(vulns, ",") + `]}`
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestIngestStreamsFeedIntoStore(t *testing.T) {
	s := openTestStore(t)
	srv := feedStub(t, "2024", feedBody(t, map[string]string{
		"CVE-2024-0001": "acme widget sql injection",
		"CVE-2024-0002": "acme widget xss",
	}))
	stubFeedBase(t, srv)

	var phases []string
	n, err := s.Ingest(context.Background(), srv.Client(), "2024", func(p IngestProgress) { phases = append(phases, p.Phase) })
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if n != 2 {
		t.Fatalf("ingested %d, want 2", n)
	}
	if phases[0] != "downloading" || phases[len(phases)-1] != "done" {
		t.Fatalf("phases: %v", phases)
	}

	res, err := s.Search(context.Background(), "acme widget", 0)
	if err != nil || len(res.Matches) != 2 {
		t.Fatalf("search after ingest: %+v %v", res, err)
	}
	// KEV flag from cisaExploitAdd.
	if !res.Matches[0].KEV {
		t.Errorf("KEV not set: %+v", res.Matches[0])
	}
	// Feed marker recorded.
	feeds, _ := s.Feeds(context.Background())
	if len(feeds) != 1 || feeds[0].Source != "2024" || feeds[0].Records != 2 || feeds[0].SHA256 == "" {
		t.Fatalf("feeds: %+v", feeds)
	}
}

func TestIngestSkipsUnchangedFeed(t *testing.T) {
	s := openTestStore(t)
	srv := feedStub(t, "modified", feedBody(t, map[string]string{"CVE-2024-0009": "x"}))
	stubFeedBase(t, srv)
	ctx := context.Background()

	if _, err := s.Ingest(ctx, srv.Client(), "modified", nil); err != nil {
		t.Fatalf("first ingest: %v", err)
	}
	n, err := s.Ingest(ctx, srv.Client(), "modified", nil)
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if n != 0 {
		t.Fatalf("unchanged feed re-ingested %d records", n)
	}
	// 且没有产生重复行。
	cnt, _ := s.Count(ctx)
	if cnt != 1 {
		t.Fatalf("count after skip: %d", cnt)
	}
}

func TestIngestInvalidSource(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Ingest(context.Background(), http.DefaultClient, "notayear", nil); err == nil {
		t.Fatal("invalid source must error")
	}
}

func TestIngestUpstreamError(t *testing.T) {
	s := openTestStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	stubFeedBase(t, srv)
	if _, err := s.Ingest(context.Background(), srv.Client(), "2024", nil); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("want 404 error, got %v", err)
	}
}
