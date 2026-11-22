package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 全局出口代理绕过修复的回归：http 类自定义工具不配 proxy、不开 use_recording_proxy
// 时，不得静默直连——必须复用 Manager.ProxyAddr 的出口逻辑（捕获关=全局代理）。
// 回环目标例外：远端出口代理够不到本机回环服务，直连打本地靶机是既有约定。
func TestHTTPToolUsesGlobalProxyByDefault(t *testing.T) {
	// 代理端：收到请求即证明出网经过了代理。
	var proxied bool
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		w.WriteHeader(200)
	}))
	defer proxySrv.Close()

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.SetGlobalProxy(proxySrv.URL); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": "http://example.com/probe"})
	if _, err := s.runHTTPTool(context.Background(), execRaw, map[string]any{}, nil); err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if !proxied {
		t.Fatal("http 工具未走全局代理：全局代理被绕过（静默直连）")
	}
}

func TestHTTPToolLoopbackStaysDirect(t *testing.T) {
	// 代理端：回环目标不应把请求发到代理（发来即失败）。
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("回环请求不应经代理转发: %s", r.URL)
		w.WriteHeader(502)
	}))
	defer proxySrv.Close()

	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer m.Close()
	if err := m.SetGlobalProxy(proxySrv.URL); err != nil {
		t.Fatal(err)
	}
	s := &Server{m: m}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()

	execRaw, _ := json.Marshal(map[string]any{"method": "GET", "url": srv.URL + "/local"})
	res, err := s.runHTTPTool(context.Background(), execRaw, map[string]any{}, nil)
	if err != nil {
		t.Fatalf("runHTTPTool: %v", err)
	}
	if res.IsError || !strings.Contains(res.Content[0].Text, `"status":200`) {
		t.Fatalf("回环直连失败: %+v", res)
	}
}

func TestIsLoopbackURL(t *testing.T) {
	hit := []string{
		"http://localhost:8787/x",
		"http://127.0.0.1:9000/x",
		"http://127.10.0.3/x", // 整个 127/8 都是回环
		"http://[::1]:8080/x",
		"http://LOCALHOST/x",
	}
	miss := []string{
		"http://example.com/x",
		"http://10.0.0.1/x",
		"http://localhost.example.com/x", // 后缀匹配不算回环
	}
	for _, u := range hit {
		if !isLoopbackURL(u) {
			t.Errorf("应判回环: %s", u)
		}
	}
	for _, u := range miss {
		if isLoopbackURL(u) {
			t.Errorf("不应判回环: %s", u)
		}
	}
}
