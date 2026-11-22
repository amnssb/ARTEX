// Package cve queries public vulnerability databases (NVD API 2.0) and returns
// compact results for the agent's cve_search tool. It is a READ-ONLY reference
// lookup: a hit here is a lead (嫌疑线索), never a confirmed finding — ARTEX's
// red line requires real exploitation evidence before report_finding, and this
// package deliberately stays out of that path.
//
// 调用示例：
//
//	res, err := cve.Search(ctx, cve.Config{}, cve.Query{Keyword: "jenkins"})
//	res, err := cve.Search(ctx, cve.Config{}, cve.Query{CVEID: "CVE-2021-44228"})
//
// Config.Proxy / Config.CACert mirror the web-search settings so deployments
// behind an egress proxy reach NVD the same way web_search does.
package cve

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// nvdEndpoint is a var so tests can stub it (nvd_test.go); production code
// never reassigns it.
var nvdEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// Config carries the outbound settings the server pushes in (mirrors the
// web-search proxy config; empty = direct).
type Config struct {
	Proxy  string
	CACert string
}

// Query is one lookup. Exactly one of CVEID / Keyword should be set; Keyword
// wins when both are present. Year range narrows keyword searches.
type Query struct {
	CVEID   string
	Keyword string
}

// Match is one compact result row: only what an agent can act on (id, score,
// affected products, fix/patch pointers). Full prose stays behind the URL.
type Match struct {
	ID          string   `json:"id"`            // CVE-YYYY-NNNN
	Summary     string   `json:"summary"`       // English description, first 500 chars
	Severity    string   `json:"severity"`      // critical/high/medium/low/unknown
	CVSS        float64  `json:"cvss"`          // best available base score (v3 > v2)
	CWE         string   `json:"cwe,omitempty"` // primary weakness, e.g. CWE-79
	Published   string   `json:"published"`     // YYYY-MM-DD
	Products    []string `json:"products"`      // CPE criteria rows (vendor:product), ≤5
	References  []string `json:"references"`    // URLs, patch/exploit-tagged first, ≤5
	KEV         bool     `json:"kev"`           // CISA Known Exploited Vulnerability
	Description string   `json:"description,omitempty"`
}

// Result is the normalized payload the tool returns as JSON.
type Result struct {
	Query   string  `json:"query"`
	Total   int     `json:"total"`
	Matches []Match `json:"matches"`
	Note    string  `json:"note"`
}

// Search runs one NVD lookup and compresses the response to Result. limit
// defaults to 5, caps at 20. Network/parse failures return an error; the tool
// layer turns that into a tool error result.
func Search(ctx context.Context, cfg Config, q Query, limit int) (*Result, error) {
	query := q.Keyword
	if strings.TrimSpace(q.CVEID) != "" && strings.TrimSpace(q.Keyword) == "" {
		query = strings.TrimSpace(q.CVEID)
	}
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("cve_search: query 不能为空（CVE 编号或关键词）")
	}
	if limit <= 0 {
		limit = 5
	}
	if limit > 20 {
		limit = 20
	}
	if IsCVEID(query) {
		query = strings.ToUpper(query) // 结果里回显规范大小写
	}

	uv := url.Values{}
	if IsCVEID(query) {
		uv.Set("cveId", strings.ToUpper(query))
	} else {
		uv.Set("keywordSearch", query)
	}
	uv.Set("resultsPerPage", fmt.Sprintf("%d", limit))

	hc, err := client(cfg)
	if err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodGet, nvdEndpoint+"?"+uv.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD 请求失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD 返回 %d（限流时稍后重试）", resp.StatusCode)
	}
	var raw struct {
		TotalResults    int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string `json:"id"`
				Published    string `json:"published"`
				Descriptions []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
				Metrics map[string]json.RawMessage `json:"metrics"`
				Weaknesses []struct {
					Description []struct {
						Value string `json:"value"`
					} `json:"description"`
				} `json:"weaknesses"`
				Configurations json.RawMessage `json:"configurations"`
				References     []struct {
					URL  string   `json:"url"`
					Tags []string `json:"tags"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("NVD 响应解析失败: %w", err)
	}

	out := &Result{Query: query, Total: raw.TotalResults}
	for _, v := range raw.Vulnerabilities {
		out.Matches = append(out.Matches, compact(v.CVE))
	}
	out.Note = "检索结果只是线索（inferred）：命中不代表已利用成功，禁止直接当作 finding 上报——必须实际触发并拿到可复现证据后走 report_finding，否则 record_fact(confidence=inferred) 交规划者。"
	return out, nil
}

// IsCVEID matches CVE-YYYY-NNNN(…): digits beyond 4 are allowed (NVD pads ids).
// Exported so the agent tool layer can route exact CVE ids to the cveId param.
func IsCVEID(s string) bool {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "CVE-") {
		return false
	}
	parts := strings.SplitN(s, "-", 3)
	if len(parts) != 3 || len(parts[1]) != 4 || len(parts[2]) < 4 {
		return false
	}
	for _, p := range parts[1:] {
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

// client builds the outbound http.Client honoring the configured proxy/CA,
// same semantics as the web-search client (empty proxy = direct).
func client(cfg Config) (*http.Client, error) {
	tr := &http.Transport{}
	if p := strings.TrimSpace(cfg.Proxy); p != "" {
		pu, err := url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("代理地址无效: %w", err)
		}
		tr.Proxy = http.ProxyURL(pu)
	}
	if ca := strings.TrimSpace(cfg.CACert); ca != "" {
		pool, err := loadCerts(ca)
		if err != nil {
			return nil, err
		}
		tr.TLSClientConfig.RootCAs = pool
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}, nil
}
