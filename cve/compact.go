package cve

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"strings"
)

// compact flattens one NVD CVE object into a Match row.
func compact(c struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics    map[string]json.RawMessage `json:"metrics"`
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
}) Match {
	m := Match{ID: c.ID}
	if len(c.Published) >= 10 {
		m.Published = c.Published[:10] // ISO 时间戳取日期部分
	}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			m.Summary = cut(d.Value, 500)
			break
		}
	}
	m.CVSS, m.Severity = bestScore(c.Metrics)
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				m.CWE = d.Value
				break
			}
		}
		if m.CWE != "" {
			break
		}
	}
	m.Products = products(c.Configurations)
	m.References = refs(c.References)
	m.KEV = kevTagged(c.References)
	return m
}

// bestScore picks the highest-priority CVSS base score: v31 → v30 → v2. The
// metric blocks each hold a vector of scored sources; the first cvssData wins.
// Severity normalizes to lowercase critical/high/medium/low/unknown.
func bestScore(metrics map[string]json.RawMessage) (float64, string) {
	pick := func(key string) (float64, string, bool) {
		raw, ok := metrics[key]
		if !ok {
			return 0, "", false
		}
		var block []struct {
			CVSSData struct {
				BaseScore float64 `json:"baseScore"`
				BaseSev   string  `json:"baseSeverity"`
			} `json:"cvssData"`
			Severity string `json:"severity"` // v2 keeps it outside cvssData
		}
		if json.Unmarshal(raw, &block) != nil || len(block) == 0 {
			return 0, "", false
		}
		sev := strings.ToLower(strings.TrimSpace(block[0].CVSSData.BaseSev))
		if sev == "" {
			sev = strings.ToLower(strings.TrimSpace(block[0].Severity))
		}
		return block[0].CVSSData.BaseScore, sev, true
	}
	for _, key := range []string{"cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		if score, sev, ok := pick(key); ok {
			if sev == "" || sev == "none" {
				sev = "unknown"
			}
			return score, sev
		}
	}
	return 0, "unknown"
}

// products extracts up to 5 CPE criteria strings ("cpe:2.3:a:vendor:product:…")
// from the CPE configuration tree. NVD sends one of two shapes — verified live
// against the API:
//   - new records: [ {operator, nodes:[{cpeMatch:[…]}]} ]  (array of config objects)
//   - old records: {nodes:[{cpeMatch:[…]}]}                (single config object)
// Unknown shapes yield nothing — configurations are optional metadata.
func products(cfgRaw json.RawMessage) []string {
	if len(cfgRaw) == 0 {
		return nil
	}
	type cpeNode struct {
		CPEMatch []struct {
			Criteria string `json:"criteria"`
		} `json:"cpeMatch"`
	}
	type cpeConfig struct {
		Nodes []cpeNode `json:"nodes"`
	}
	var configs []cpeConfig
	if json.Unmarshal(cfgRaw, &configs) != nil || len(configs) == 0 {
		var single cpeConfig
		if json.Unmarshal(cfgRaw, &single) != nil || len(single.Nodes) == 0 {
			return nil
		}
		configs = []cpeConfig{single}
	}
	seen := map[string]bool{}
	var out []string
	for _, cfg := range configs {
		for _, n := range cfg.Nodes {
			for _, c := range n.CPEMatch {
				if seen[c.Criteria] {
					continue
				}
				seen[c.Criteria] = true
				out = append(out, c.Criteria)
				if len(out) >= 5 {
					return out
				}
			}
		}
	}
	return out
}

// refs orders references patch/exploit-tagged first and caps at 5, so the
// exploit-adjacent URLs an agent needs survive the cut.
func refs(list []struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}) []string {
	var hot, rest []string
	for _, r := range list {
		interesting := false
		for _, t := range r.Tags {
			switch strings.ToLower(t) {
			case "patch", "exploit", "exploitability", "technical details", "third party advisory", "vendor advisory":
				interesting = true
			}
		}
		if interesting {
			hot = append(hot, r.URL)
		} else {
			rest = append(rest, r.URL)
		}
	}
	out := append(hot, rest...)
	if len(out) > 5 {
		out = out[:5]
	}
	return out
}

// kevTagged reports the CISA Known Exploited tag NVD adds via cveTags; when
// absent (some records), fall back to a reference tagged "exploited"? No — the
// API surface here only carries references, so we accept false negatives.
func kevTagged(list []struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}) bool {
	for _, r := range list {
		for _, t := range r.Tags {
			if strings.EqualFold(t, "exploited") || strings.EqualFold(t, "known exploited") {
				return true
			}
		}
	}
	return false
}

// loadCerts reads a PEM CA bundle for MITM deployments (same shape as the
// web-search client's CACert option).
func loadCerts(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errNoCerts
	}
	return pool, nil
}

// cut truncates s to at most n runes.
func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return strings.TrimSpace(string(r[:n])) + "…"
}

type certError string

func (e certError) Error() string { return string(e) }

const errNoCerts = certError("CA 证书文件解析失败")
