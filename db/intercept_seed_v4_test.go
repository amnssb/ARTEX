package db

import (
	"regexp"
	"testing"
)

// 内置「显式绕过出口代理」规则匹配整个 tool_input JSON 串，用例以 JSON 形态给出，
// 与 Interceptor 实际拿到的 subject 一致。
func TestProxyBypassPatterns(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		hit     []string
		miss    []string
	}{
		{
			name:    "env 操作面",
			pattern: proxyBypassUnsetPattern,
			hit: []string{
				`{"command":"unset HTTP_PROXY && curl http://t.com"}`,
				`{"command":"unset http_proxy https_proxy ALL_PROXY; nmap -p80 10.0.0.1"}`,
				`{"command":"HTTP_PROXY= curl http://t.com"}`,
				`{"command":"http_proxy= https_proxy= python3 scan.py"}`,
				`{"command":"env -u HTTPS_PROXY curl http://t.com"}`,
				`{"command":"export NO_PROXY='*' && curl http://t.com"}`,
				`{"command":"env --unset=all_proxy wget http://t.com"}`,
			},
			miss: []string{
				`{"command":"curl -x http://127.0.0.1:8788 http://t.com"}`, // 显式走代理，合法
				`{"command":"echo $HTTP_PROXY"}`,                          // 读变量不是清空
				`{"command":"unset BUILD_NUMBER"}`,
				`{"command":"cat /tmp/https_proxy_check.txt"}`, // 文件名带 proxy 词，非 env 操作
			},
		},
		{
			name:    "curl/wget --noproxy",
			pattern: proxyBypassNoproxyPattern,
			hit: []string{
				`{"command":"curl --noproxy '*' http://t.com"}`,
				`{"command":"curl -s --noproxy 10.0.0.1 http://t.com"}`,
				`{"command":"wget --no-proxy http://t.com/x"}`,
			},
			miss: []string{
				`{"command":"curl --proxy http://127.0.0.1:8788 http://t.com"}`,
				`{"command":"curl http://t.com --noproxified-not"}`, // 词干不同不误拦
			},
		},
		{
			name:    "trust_env=False",
			pattern: proxyBypassTrustEnvPattern,
			hit: []string{
				`{"code":"import requests\ns=requests.Session()\ns.trust_env=False\ns.get('http://t.com')"}`,
				`{"code":"httpx.Client(trust_env=False)"}`,
			},
			miss: []string{
				`{"code":"s.trust_env=True"}`,
			},
		},
		{
			name:    "NO_PROXY=*",
			pattern: proxyBypassNoProxyPattern,
			hit: []string{
				`{"command":"NO_PROXY='*' curl http://t.com"}`,
				`{"command":"export no_proxy=*; scan"}`,
				`{"command":"NO_PROXY=* curl http://t.com"}`,
			},
			miss: []string{
				`{"command":"NO_PROXY=10.0.0.1,127.0.0.1 curl http://127.0.0.1:8788"}`, // 回环豁免合法
			},
		},
		{
			name:    "undici dispatcher 置空",
			pattern: proxyBypassDispatcherPattern,
			hit: []string{
				`{"code":"setGlobalDispatcher(new Agent())"}`,
				`{"code":"const {setGlobalDispatcher, ProxyAgent} = require('undici'); setGlobalDispatcher(new undici.ProxyAgent(undefined))"}`,
				`{"code":"setGlobalDispatcher(new Agent({}))"}`,
			},
			miss: []string{
				`{"code":"setGlobalDispatcher(new ProxyAgent('http://127.0.0.1:8788'))"}`, // 显式指向代理
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			re := regexp.MustCompile(tc.pattern)
			for _, s := range tc.hit {
				if !re.MatchString(s) {
					t.Errorf("应命中却放行: %s", s)
				}
			}
			for _, s := range tc.miss {
				if re.MatchString(s) {
					t.Errorf("误拦: %s", s)
				}
			}
		})
	}
}
