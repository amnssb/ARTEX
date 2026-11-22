package cve

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nvdStub serves a canned NVD API 2.0 response for the endpoint cve.go dials;
// swapping the package const keeps the test hermetic (no external network).
func nvdStub(t *testing.T, payload string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		if !strings.HasSuffix(r.URL.Path, "/rest/json/cves/2.0") && r.URL.Path != "/" {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// stubEndpoint points the package at the stub for the duration of one test.
func stubEndpoint(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := nvdEndpoint
	nvdEndpoint = srv.URL
	t.Cleanup(func() { nvdEndpoint = old })
}

const log4jPayload = `{
  "resultsPerPage": 1, "totalResults": 1, "version": "2.0",
  "vulnerabilities": [{
    "cve": {
      "id": "CVE-2021-44228",
      "published": "2021-12-10T10:15:09.143",
      "descriptions": [
        {"lang": "en", "value": "Apache Log4j2 JNDI features used in configuration do not protect against attacker controlled LDAP. "},
        {"lang": "zh", "value": "忽略"}
      ],
      "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]
      },
      "weaknesses": [{"description": [{"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "CWE-502"}]}],
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"},
        {"criteria": "cpe:2.3:a:apache:log4j:2.14:*:*:*:*:*:*:*"}
      ]}]}],
      "references": [
        {"url": "https://logging.apache.org/log4j/2.x/security.html", "tags": ["Vendor Advisory"]},
        {"url": "https://github.com/apache/logging-log4j2/commit/xyz", "tags": ["Patch"]},
        {"url": "https://example.com/wp", "tags": []}
      ]
    }
  }]
}`

func TestSearchByCVEID(t *testing.T) {
	srv := nvdStub(t, log4jPayload)
	stubEndpoint(t, srv)

	res, err := Search(context.Background(), Config{}, Query{CVEID: "cve-2021-44228"}, 0)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if res.Query != "CVE-2021-44228" || res.Total != 1 || len(res.Matches) != 1 {
		t.Fatalf("unexpected result: %+v", res)
	}
	m := res.Matches[0]
	if m.ID != "CVE-2021-44228" {
		t.Errorf("id: %q", m.ID)
	}
	if m.CVSS != 10.0 || m.Severity != "critical" {
		t.Errorf("score/severity: %v/%q", m.CVSS, m.Severity)
	}
	if m.CWE != "CWE-917" {
		t.Errorf("cwe: %q", m.CWE)
	}
	if m.Published != "2021-12-10" {
		t.Errorf("published cut: %q", m.Published)
	}
	if len(m.Products) != 2 || !strings.HasPrefix(m.Products[0], "cpe:2.3:a:apache:log4j") {
		t.Errorf("products: %v", m.Products)
	}
	// patch/vendor-advisory 引用排前面，普通引用垫底。
	if len(m.References) != 3 || m.References[0] != "https://logging.apache.org/log4j/2.x/security.html" {
		t.Errorf("references ordering: %v", m.References)
	}
	if !strings.Contains(res.Note, "report_finding") {
		t.Errorf("红线说明缺失: %q", res.Note)
	}
}

func TestSearchByKeyword(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotQuery = r.Form.Get("keywordSearch")
		_, _ = w.Write([]byte(log4jPayload))
	}))
	defer srv.Close()
	stubEndpoint(t, srv)

	if _, err := Search(context.Background(), Config{}, Query{Keyword: "jenkins"}, 3); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if gotQuery != "jenkins" {
		t.Errorf("keywordSearch not forwarded: %q", gotQuery)
	}
}

func TestSearchEmptyQuery(t *testing.T) {
	if _, err := Search(context.Background(), Config{}, Query{}, 5); err == nil {
		t.Fatal("empty query must error")
	}
}

func TestSearchUpstreamError(t *testing.T) {
	srv := nvdStub(t, `{"message":"rate limited"}`)
	// status 403 模拟限流。
	old := nvdEndpoint
	srv.Close()
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer limited.Close()
	nvdEndpoint = limited.URL
	t.Cleanup(func() { nvdEndpoint = old })

	_, err := Search(context.Background(), Config{}, Query{Keyword: "x"}, 5)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want upstream status error, got %v", err)
	}
}

func TestSearchLimitBounds(t *testing.T) {
	var gotPerPage string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotPerPage = r.Form.Get("resultsPerPage")
		_, _ = w.Write([]byte(log4jPayload))
	}))
	defer srv.Close()
	stubEndpoint(t, srv)

	if _, err := Search(context.Background(), Config{}, Query{Keyword: "x"}, 99); err != nil {
		t.Fatalf("Search: %v", err)
	}
	if gotPerPage != "20" {
		t.Errorf("limit not capped at 20: %q", gotPerPage)
	}
}

func TestIsCVEID(t *testing.T) {
	hit := []string{"CVE-2021-44228", "cve-2024-1234", "CVE-2025-000001"}
	miss := []string{"log4j rce", "CVE-2021", "CVE-2021-x", "cve-2021-44228x", "CWE-79"}
	for _, s := range hit {
		if !IsCVEID(s) {
			t.Errorf("应判为 CVE id: %s", s)
		}
	}
	for _, s := range miss {
		if IsCVEID(s) {
			t.Errorf("不应判为 CVE id: %s", s)
		}
	}
}

func TestBestScoreFallbackChain(t *testing.T) {
	// v2-only 记录：baseSeverity 为空时回落外层 severity 字段。
	m := map[string]json.RawMessage{
		"cvssMetricV2": json.RawMessage(`[{"cvssData":{"baseScore":7.5},"severity":"HIGH"}]`),
	}
	score, sev := bestScore(m)
	if score != 7.5 || sev != "high" {
		t.Errorf("v2 fallback: %v/%q", score, sev)
	}
	// 无任何 metric → unknown。
	score, sev = bestScore(map[string]json.RawMessage{})
	if score != 0 || sev != "unknown" {
		t.Errorf("empty metrics: %v/%q", score, sev)
	}
}
