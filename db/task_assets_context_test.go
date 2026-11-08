package db

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestCountHostsByTaskWithSourcesMatchesHostList locks the snapshot's host
// total to the same identity as the host list: trimmed lowercased domain and
// ip, plus a URL hostname, with rejected URLs contributing nothing. The count
// is what graph_overview reports; if it drifts, inherited and company hosts
// silently disappear from the planner's context.
func TestCountHostsByTaskWithSourcesMatchesHostList(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()

	task, err := d.CreateTask("host count parity", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	other, err := d.CreateTask("host count outsider", "goal", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(other.ID) })

	suffix := time.Now().UnixNano()
	domain := fmt.Sprintf("  Domain-%d.Example  ", suffix)
	ip := fmt.Sprintf("2001:DB8:%x:%x::10", uint64(suffix)&0xffff, (uint64(suffix)>>16)&0xffff)
	userHost := fmt.Sprintf("UserInfo-%d.Invalid", suffix)
	userURL := fmt.Sprintf("http://user:pass@%s:8080/a", userHost)
	v6 := fmt.Sprintf("2001:db8:%x:%x::42", uint64(suffix>>32)&0xffff, uint64(suffix>>48)&0xffff)
	v6URL := fmt.Sprintf("http://[%s]:8443/a", v6)
	dup := fmt.Sprintf("dup-%d.invalid", suffix)
	dupURL := "http://" + strings.ToUpper(dup) + "/path"
	svcDomain := fmt.Sprintf("svc-%d.invalid", suffix)
	svcIP := fmt.Sprintf("2001:DB8:%x:%x::20", uint64(suffix)&0xffff, (uint64(suffix)>>20)&0xffff)
	svcURL := fmt.Sprintf("http://%s/x", svcDomain)
	badURL := fmt.Sprintf("not-a-url-%d", suffix)
	badPortURL := fmt.Sprintf("http://badport-%d.invalid:notaport/x", suffix)
	relative := fmt.Sprintf("relative-%d.invalid", suffix)
	relativeURL := "//" + relative + "/a"
	embeddedAt := fmt.Sprintf("AtHost-%d.Invalid", suffix)
	embeddedAtURL := fmt.Sprintf("https://user:p@ss@%s/x", embeddedAt)
	queryAt := fmt.Sprintf("queryat-%d.invalid", suffix)
	queryAtURL := fmt.Sprintf("http://%s/path?x=@y", queryAt)
	outsider := fmt.Sprintf("outsider-%d.invalid", suffix)

	type row struct {
		typ, domain, ip, rawURL, serviceType, method string
	}
	rows := []row{
		{typ: "root_domain", domain: domain},
		{typ: "ip", ip: ip},
		{typ: "service", rawURL: userURL, serviceType: "http"},
		{typ: "service", rawURL: v6URL, serviceType: "http"},
		{typ: "service", domain: dup, rawURL: dupURL, serviceType: "http"},
		{typ: "service", domain: svcDomain, ip: svcIP, rawURL: svcURL, serviceType: "http"},
		{typ: "service", domain: "   ", rawURL: badURL, serviceType: "http"},
		{typ: "service", rawURL: badPortURL, serviceType: "http"},
		{typ: "endpoint", rawURL: relativeURL, method: "GET"},
		{typ: "service", rawURL: embeddedAtURL, serviceType: "http"},
		{typ: "service", rawURL: queryAtURL, serviceType: "http"},
	}
	var ids []int64
	t.Cleanup(func() {
		if len(ids) > 0 {
			_, _ = d.Assets().DeleteByIDs(ids)
		}
	})
	insert := func(taskID int64, r row) {
		t.Helper()
		var id int64
		err := d.QueryRow(`
INSERT INTO assets(type, domain, ip, url, service_type, method, task_ids)
VALUES ($1, NULLIF($2, ''), NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7::bigint[])
RETURNING id`, r.typ, r.domain, r.ip, r.rawURL, r.serviceType, r.method, []int64{taskID}).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	for _, r := range rows {
		insert(task.ID, r)
	}
	insert(other.ID, row{typ: "root_domain", domain: outsider})

	want := map[string]struct{}{}
	add := func(host string) {
		host = strings.TrimSpace(strings.ToLower(host))
		if host != "" {
			want[host] = struct{}{}
		}
	}
	for _, r := range rows {
		add(r.domain)
		add(r.ip)
		if parsed, err := url.Parse(r.rawURL); err == nil {
			add(parsed.Hostname())
		}
	}

	hosts, err := d.Assets().HostsByTaskWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != len(want) {
		t.Fatalf("host list = %v, want %d hosts from fixtures", hosts, len(want))
	}
	for _, host := range hosts {
		if _, ok := want[host]; !ok {
			t.Fatalf("host list has %q, fixtures produce %v", host, hosts)
		}
	}
	got, err := d.Assets().CountHostsByTaskWithSources(task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != len(hosts) {
		t.Fatalf("CountHostsByTaskWithSources=%d HostsByTaskWithSources=%v", got, hosts)
	}
}
