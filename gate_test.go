package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}

// 換一個乾淨的封鎖表，時間由回傳的指標控制
func freshBlocker(t *testing.T) *time.Time {
	t.Helper()
	old := blk
	t.Cleanup(func() { blk = old })
	now := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	blk = newBlocker()
	blk.now = func() time.Time { return now }
	return &now
}

func TestSafeNext(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/", "/"},
		{"/webman/index.cgi?a=1", "/webman/index.cgi?a=1"},
		{"/dir/", "/dir/"},
		{"/a/b/../c?x=1", "/a/c?x=1"},
		{"//evil.com", "/"},
		{`/\evil.com`, "/"},
		{`/./\evil.com`, "/"},
		{`/../\evil.com`, "/"},
		{`/a/../\evil.com`, "/"},
		{"/\t/evil.com", "/"},
		{"/\n/evil.com", "/"},
		{"/\r/evil.com", "/"},
		{"https://evil.com", "/"},
		{"evil.com", "/"},
		{"", "/"},
	}
	for _, c := range cases {
		got := safeNext(c.in)
		if got != c.want {
			t.Errorf("safeNext(%q) = %q, want %q", c.in, got, c.want)
		}
		// http.Redirect 會再整理一次路徑，實際寫出的 Location 也不能變成協定相對網址
		rec := httptest.NewRecorder()
		http.Redirect(rec, httptest.NewRequest("POST", "/__gate/verify", nil), got, http.StatusSeeOther)
		if loc := rec.Header().Get("Location"); strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, `/\`) {
			t.Errorf("safeNext(%q): Location %q", c.in, loc)
		}
	}
}

func TestHasDotDot(t *testing.T) {
	cases := map[string]bool{
		"/webdav/../x":     true,
		`/webdav/a/..\x`:   true,
		"/webdav/..hidden": false,
		"/webdav/a..b/":    false,
		"/webdav/":         false,
	}
	for in, want := range cases {
		if got := hasDotDot(in); got != want {
			t.Errorf("hasDotDot(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAllowedHost(t *testing.T) {
	defer func(old []string) { allowedHosts = old }(allowedHosts)

	allowedHosts = nil
	if !allowedHost("anything.example:1234") {
		t.Error("empty list should allow any host")
	}

	allowedHosts = []string{"ninja.example.me"}
	cases := map[string]bool{
		"ninja.example.me":       true,
		"NINJA.example.me:8443":  true,
		"ninja.example.me.":      true,
		"Ninja.Example.Me.:8443": true,
		"ninja.example.me..":     false,
		"[::1]:8443":             false,
		"[::1]":                  false,
		"other.example.me":       false,
		"192.168.1.1":            false,
		"":                       false,
	}
	for in, want := range cases {
		if got := allowedHost(in); got != want {
			t.Errorf("allowedHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCookieState(t *testing.T) {
	defer func(old []byte) { gateKey = old }(gateKey)
	gateKey = []byte("test-key")

	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	good := future + "." + sign(future)
	gateKey = []byte("other-key")
	otherKey := future + "." + sign(future)
	gateKey = []byte("test-key")
	flip := byte('0')
	if good[len(good)-1] == '0' {
		flip = '1'
	}
	tampered := good[:len(good)-1] + string(flip)
	expired := past + "." + sign(past)
	malformed := "garbage"

	cases := []struct {
		name string
		vals []string
		want cookieStatus
	}{
		{"none", nil, cookieNone},
		{"valid", []string{good}, cookieValid},
		{"expired", []string{expired}, cookieExpired},
		{"tampered sig", []string{tampered}, cookieBadSig},
		{"tampered exp", []string{future + "1." + sign(future)}, cookieBadSig},
		{"other key", []string{otherKey}, cookieBadSig},
		{"uppercase hex", []string{future + "." + strings.ToUpper(sign(future))}, cookieBadSig},
		{"no dot", []string{future + sign(future)}, cookieMalformed},
		{"non-numeric", []string{"abc." + sign("abc")}, cookieMalformed},
		{"short sig", []string{future + ".abcd"}, cookieMalformed},
		{"non-hex sig", []string{future + "." + strings.Repeat("z", 64)}, cookieMalformed},
		{"empty value ignored", []string{""}, cookieNone},
		{"malformed+valid", []string{malformed, good}, cookieValid},
		{"badsig+valid", []string{otherKey, good}, cookieValid},
		{"malformed+badsig", []string{malformed, otherKey}, cookieBadSig},
		{"malformed+expired", []string{expired, malformed}, cookieExpired},
		{"all malformed", []string{malformed, "x.y"}, cookieMalformed},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		for _, v := range c.vals {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: v})
		}
		r.AddCookie(&http.Cookie{Name: "other", Value: "garbage"})
		if got := cookieState(r); got != c.want {
			t.Errorf("%s: cookieState = %v, want %v", c.name, got, c.want)
		}
	}
}

func postVerify(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/__gate/verify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "203.0.113.5:1234"
	r.Host = "example.com"
	rec := httptest.NewRecorder()
	verify(rec, r)
	return rec
}

// 超過上限，在呼叫 siteverify 之前就回 413（不會連線）
func TestVerifyBodyLimit(t *testing.T) {
	freshBlocker(t)
	rec := postVerify("next=/&cf-turnstile-response=" + strings.Repeat("a", 9000))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rec.Code)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("cookie set")
	}
	if blk.blocked("203.0.113.5") {
		t.Error("blocked on oversized body")
	}
}

// 沒有 token 時 siteverify 不會連線，直接導回驗證頁，且是強訊號
func TestVerifyNoToken(t *testing.T) {
	freshBlocker(t)
	rec := postVerify("next=/x")
	want := "/__gate?err=1&next=" + url.QueryEscape("/x")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Errorf("got %d %q, want 303 %q", rec.Code, rec.Header().Get("Location"), want)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("cookie set without verification")
	}
	if !blk.blocked("203.0.113.5") {
		t.Error("empty token not blocked")
	}
}

// body 沒讀完（使用者中途離開、連線中斷）或格式錯誤：回 400，不呼叫 siteverify、不封鎖
func TestVerifyBadBody(t *testing.T) {
	freshBlocker(t)
	for name, body := range map[string]io.Reader{
		"interrupted": io.MultiReader(strings.NewReader("next=/x&cf-turnstile-response=ab"), errReader{}),
		"bad escape":  strings.NewReader("cf-turnstile-response=abc%zz"),
	} {
		r := httptest.NewRequest("POST", "/__gate/verify", body)
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.RemoteAddr = "203.0.113.5:1234"
		rec := httptest.NewRecorder()
		verify(rec, r)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, rec.Code)
		}
		if blk.blocked("203.0.113.5") {
			t.Fatalf("%s: blocked", name)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestVerifySignals(t *testing.T) {
	defer func(old string) { siteverifyURL = old }(siteverifyURL)
	defer func(old []byte) { gateKey = old }(gateKey)
	gateKey = []byte("k")

	cases := []struct {
		name      string
		resp      string
		afterOne  bool // 第 1 次後是否封鎖
		afterTwo  bool // 10 分鐘內第 2 次後是否封鎖
		wantOK    bool
		transport bool // 模擬連線錯誤
	}{
		{"success", `{"success":true,"hostname":"example.com"}`, false, false, true, false},
		{"success trailing dot", `{"success":true,"hostname":"EXAMPLE.com."}`, false, false, true, false},
		{"hostname mismatch", `{"success":true,"hostname":"evil.com"}`, true, true, false, false},
		{"invalid-input-response", `{"success":false,"error-codes":["invalid-input-response"]}`, true, true, false, false},
		{"bad-request", `{"success":false,"error-codes":["bad-request"]}`, true, true, false, false},
		{"timeout-or-duplicate", `{"success":false,"error-codes":["timeout-or-duplicate"]}`, false, true, false, false},
		{"missing-input-secret", `{"success":false,"error-codes":["missing-input-secret"]}`, false, false, false, false},
		{"invalid-input-secret", `{"success":false,"error-codes":["invalid-input-secret","invalid-input-response"]}`, false, false, false, false},
		{"internal-error", `{"success":false,"error-codes":["internal-error"]}`, false, false, false, false},
		{"no codes", `{"success":false}`, false, false, false, false},
		{"bad json", `not json`, false, false, false, false},
		{"connection error", "", false, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := freshBlocker(t)
			sv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.ParseForm()
				if r.PostFormValue("response") != "tok" || r.PostFormValue("remoteip") != "203.0.113.5" {
					t.Errorf("unexpected form %v", r.PostForm)
				}
				io.WriteString(w, c.resp)
			}))
			siteverifyURL = sv.URL
			if c.transport {
				sv.Close()
			} else {
				defer sv.Close()
			}

			rec := postVerify("next=/x&cf-turnstile-response=tok")
			if ok := strings.Contains(rec.Header().Get("Set-Cookie"), cookieName+"="); ok != c.wantOK {
				t.Fatalf("cookie set = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK && !strings.HasPrefix(rec.Header().Get("Location"), "/__gate?err=1") {
				t.Errorf("Location %q", rec.Header().Get("Location"))
			}
			if got := blk.blocked("203.0.113.5"); got != c.afterOne {
				t.Fatalf("after 1st: blocked = %v, want %v", got, c.afterOne)
			}
			*now = now.Add(5 * time.Minute)
			postVerify("next=/x&cf-turnstile-response=tok")
			if got := blk.blocked("203.0.113.5"); got != c.afterTwo {
				t.Errorf("after 2nd: blocked = %v, want %v", got, c.afterTwo)
			}
		})
	}
}

func TestBlockerDurations(t *testing.T) {
	now := freshBlocker(t)
	const ip = "203.0.113.9"
	steps := []struct {
		advance time.Duration
		want    time.Duration
	}{
		{0, time.Hour},
		{2 * time.Hour, 24 * time.Hour},
		{25 * time.Hour, 7 * 24 * time.Hour},
	}
	for i, s := range steps {
		*now = now.Add(s.advance)
		if !blk.hit(ip, "bad_cookie", "") {
			t.Fatalf("step %d: not blocked", i)
		}
		if got := blk.m[ip].until.Sub(*now); got != s.want {
			t.Errorf("step %d: duration %v, want %v", i, got, s.want)
		}
	}
	if !blk.blocked("::ffff:" + ip) {
		t.Error("IPv4-mapped form not blocked")
	}
	// 已在封鎖中再觸發不加重
	strikes := blk.m[ip].strikes
	blk.hit(ip, "bad_cookie", "")
	if blk.m[ip].strikes != strikes {
		t.Error("strike added while blocked")
	}
	// 最後一次封鎖超過 7 天 → 歸零，重新從 1 小時開始
	*now = now.Add(15 * 24 * time.Hour)
	blk.hit(ip, "bad_cookie", "")
	if o := blk.m[ip]; o.strikes != 1 || o.until.Sub(*now) != time.Hour {
		t.Errorf("after 7-day window: strikes %d, duration %v", o.strikes, o.until.Sub(*now))
	}
	*now = now.Add(time.Hour)
	if blk.blocked(ip) {
		t.Error("still blocked after expiry")
	}
}

func TestBlockerWeak(t *testing.T) {
	now := freshBlocker(t)
	const ip = "198.51.100.7"
	if blk.hit(ip, "verify_fail", "weak") {
		t.Fatal("1st weak blocked")
	}
	*now = now.Add(11 * time.Minute)
	if blk.hit(ip, "verify_fail", "weak") {
		t.Fatal("weak after 11 min blocked")
	}
	*now = now.Add(9 * time.Minute)
	if !blk.hit(ip, "verify_fail", "weak") {
		t.Fatal("2nd weak within 10 min not blocked")
	}
	if blk.m[ip].strikes != 1 {
		t.Errorf("strikes %d", blk.m[ip].strikes)
	}
}

func TestBlockerPrivate(t *testing.T) {
	freshBlocker(t)
	for _, ip := range []string{"10.1.2.3", "172.17.0.1", "192.168.1.5", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.5", "not-an-ip", ""} {
		if blk.hit(ip, "bad_cookie", "") || blk.blocked(ip) {
			t.Errorf("%q blocked", ip)
		}
	}
	if len(blk.m) != 0 {
		t.Errorf("table has %d entries", len(blk.m))
	}
}

func TestBlockerFull(t *testing.T) {
	now := freshBlocker(t)
	blk.max = 3
	blk.hit("203.0.113.1", "bad_cookie", "")
	*now = now.Add(time.Minute)
	blk.hit("203.0.113.2", "bad_cookie", "")
	*now = now.Add(time.Minute)
	blk.hit("203.0.113.3", "bad_cookie", "")
	// 全部封鎖中 → 拒絕新增
	if blk.hit("203.0.113.4", "bad_cookie", "") || len(blk.m) != 3 {
		t.Fatalf("added while table full of blocked entries: %d", len(blk.m))
	}
	// 最早解封前不再掃描
	if want := now.Add(-2*time.Minute + time.Hour); !blk.fullTill.Equal(want) {
		t.Errorf("fullTill = %v, want %v", blk.fullTill, want)
	}
	// .1、.2 解除封鎖（只剩累犯紀錄），淘汰 lastHit 最舊的 .1
	*now = now.Add(time.Hour - time.Second)
	if !blk.hit("203.0.113.4", "bad_cookie", "") {
		t.Fatal("new attacker not blocked")
	}
	if _, ok := blk.m["203.0.113.1"]; ok {
		t.Error("oldest entry not evicted")
	}
	if _, ok := blk.m["203.0.113.2"]; !ok {
		t.Error("wrong entry evicted")
	}
	if len(blk.m) != 3 {
		t.Errorf("entries %d", len(blk.m))
	}
}

func TestBlockerSweep(t *testing.T) {
	now := freshBlocker(t)
	blk.hit("203.0.113.1", "bad_cookie", "")
	blk.hit("203.0.113.2", "verify_fail", "weak")
	if n, b := blk.sweep(); n != 2 || b != 1 {
		t.Fatalf("sweep = %d,%d", n, b)
	}
	*now = now.Add(11 * time.Minute)
	if n, b := blk.sweep(); n != 1 || b != 1 {
		t.Fatalf("after 11m sweep = %d,%d", n, b)
	}
	*now = now.Add(2 * time.Hour)
	if n, b := blk.sweep(); n != 1 || b != 0 {
		t.Fatalf("after unblock sweep = %d,%d (strike record kept)", n, b)
	}
	*now = now.Add(7 * 24 * time.Hour)
	if n, _ := blk.sweep(); n != 0 {
		t.Fatalf("after 7d sweep = %d", n)
	}
}

func TestBlockListener(t *testing.T) {
	freshBlocker(t)
	blk.now = time.Now
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := blockListener{raw, blk}
	// loopback 不會經由 hit 封鎖，測試直接寫入表格
	blk.m["127.0.0.1"] = &offender{until: time.Now().Add(time.Hour)}

	got := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			got <- c
		}
	}()

	c1, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c1.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c1.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("blocked conn not closed: %v", err)
	}
	select {
	case <-got:
		t.Fatal("blocked conn returned from Accept")
	default:
	}

	blk.mu.Lock()
	delete(blk.m, "127.0.0.1")
	blk.mu.Unlock()
	c2, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	select {
	case c := <-got:
		if c.RemoteAddr().String() != c2.LocalAddr().String() {
			t.Errorf("accepted %v, want %v", c.RemoteAddr(), c2.LocalAddr())
		}
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("unblocked conn not accepted")
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestHandler(t *testing.T) {
	freshBlocker(t)
	defer func(old []string) { allowedHosts = old }(allowedHosts)
	defer func(old []byte) { gateKey = old }(gateKey)
	allowedHosts = []string{"example.com"}
	gateKey = []byte("k")
	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	good := future + "." + sign(future)
	gateKey = []byte("old")
	stale := future + "." + sign(future)
	gateKey = []byte("k")

	proxied := false
	h := newHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		io.WriteString(w, "upstream")
	}))
	do := func(ip, host, p string, cookies ...string) *httptest.ResponseRecorder {
		proxied = false
		r := httptest.NewRequest("GET", p, nil)
		r.RemoteAddr = ip + ":1234"
		r.Host = host
		r.Header.Set("Accept", "text/html")
		for _, v := range cookies {
			r.AddCookie(&http.Cookie{Name: cookieName, Value: v})
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	for _, host := range []string{"1.2.3.4", "other.com", "[::1]:8443"} {
		if rec := do("203.0.113.1", host, "/"); rec.Code != http.StatusMisdirectedRequest {
			t.Errorf("host %q: %d, want 421", host, rec.Code)
		}
	}
	for _, host := range []string{"EXAMPLE.com", "example.com.", "example.com:8443"} {
		if rec := do("203.0.113.1", host, "/", good); rec.Code != http.StatusOK || !proxied {
			t.Errorf("host %q: %d proxied=%v", host, rec.Code, proxied)
		}
	}
	if blk.blocked("203.0.113.1") {
		t.Fatal("host mismatch blocked")
	}

	// 驗證頁有安全標頭，轉發的回應沒有
	rec := do("203.0.113.1", "example.com", "/__gate")
	for k, v := range map[string]string{"Content-Security-Policy": "frame-ancestors 'none'", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("/__gate %s = %q", k, got)
		}
	}
	rec = do("203.0.113.1", "example.com", "/x", good)
	if rec.Header().Get("Content-Security-Policy") != "" || rec.Header().Get("Referrer-Policy") != "" {
		t.Error("security headers on proxied response")
	}

	// 沒有 cookie → 導向驗證頁，不算事件
	rec = do("203.0.113.2", "example.com", "/x")
	if rec.Code != http.StatusFound || rec.Header().Get("Set-Cookie") != "" {
		t.Errorf("none: %d %q", rec.Code, rec.Header().Get("Set-Cookie"))
	}
	// 換了 GATE_KEY → 清除 cookie、導向驗證頁、不封鎖
	rec = do("203.0.113.2", "example.com", "/x", stale)
	sc := rec.Header().Get("Set-Cookie")
	if rec.Code != http.StatusFound || !strings.Contains(sc, cookieName+"=;") || !strings.Contains(sc, "Max-Age=0") || !strings.Contains(sc, "Path=/") {
		t.Errorf("badsig: %d %q", rec.Code, sc)
	}
	// 一個格式錯誤加一個有效 → 放行
	if rec = do("203.0.113.2", "example.com", "/x", "junk", good); !proxied {
		t.Errorf("malformed+valid: %d", rec.Code)
	}
	if blk.blocked("203.0.113.2") {
		t.Fatal("blocked without bad_cookie")
	}

	// 全部格式錯誤 → bad_cookie → 403 並封鎖；之後的請求 403 + Connection: close
	rec = do("203.0.113.3", "example.com", "/x", "junk", "a.b")
	if rec.Code != http.StatusForbidden || !blk.blocked("203.0.113.3") {
		t.Fatalf("bad_cookie: %d blocked=%v", rec.Code, blk.blocked("203.0.113.3"))
	}
	rec = do("203.0.113.3", "example.com", "/x", good)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Connection") != "close" || proxied {
		t.Errorf("blocked request: %d %q", rec.Code, rec.Header().Get("Connection"))
	}

	// 私有 IP：照樣 403，但不封鎖
	if rec = do("192.168.1.5", "example.com", "/x", "junk"); rec.Code != http.StatusForbidden {
		t.Errorf("private bad_cookie: %d", rec.Code)
	}
	if rec = do("192.168.1.5", "example.com", "/x", good); !proxied {
		t.Error("private IP blocked")
	}
}

func TestTrustCFBlocked(t *testing.T) {
	freshBlocker(t)
	defer func(old bool) { trustCF = old }(trustCF)
	trustCF = true
	blk.hit("203.0.113.8", "bad_cookie", "")
	h := newHandler(http.NotFoundHandler())
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.8")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Connection") != "close" {
		t.Errorf("got %d %q", rec.Code, rec.Header().Get("Connection"))
	}
}

func TestBlocklist(t *testing.T) {
	now := freshBlocker(t)
	blk.hit("203.0.113.50", "bad_cookie", "")
	blk.hit("2001:db8::1", "bad_cookie", "")
	blk.hit("198.51.100.7", "verify_fail", "strong")
	blk.hit("198.51.100.8", "verify_fail", "weak") // 只有紀錄，未封鎖
	blk.m["198.51.100.9"] = &offender{until: now.Add(-time.Second), strikes: 1, lastHit: now.Add(-time.Hour)}
	*now = now.Add(60 * time.Second)

	get := func(method, p string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		serveBlocklist(rec, httptest.NewRequest(method, p, nil))
		return rec
	}
	rec := get("GET", "/blocklist.json")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("got %d %v", rec.Code, rec.Header())
	}
	var out struct {
		Generated string  `json:"generated"`
		Items     []entry `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Generated != "2026-10-31T09:01:00Z" {
		t.Errorf("generated %q", out.Generated)
	}
	want := map[string]entry{
		"203.0.113.50": {"203.0.113.50", 3540, "bad_cookie", 1},
		"198.51.100.7": {"198.51.100.7", 3540, "verify_fail", 1},
	}
	if len(out.Items) != len(want) {
		t.Fatalf("items %+v", out.Items)
	}
	for _, it := range out.Items {
		if want[it.IP] != it {
			t.Errorf("item %+v", it)
		}
	}

	// 沒有項目時是空陣列，不是 null
	freshBlocker(t)
	if body := get("GET", "/blocklist.json").Body.String(); !strings.Contains(body, `"items":[]`) {
		t.Errorf("empty body %q", body)
	}
	for _, c := range []struct {
		method, path string
		code         int
	}{
		{"POST", "/blocklist.json", http.StatusMethodNotAllowed},
		{"HEAD", "/blocklist.json", http.StatusMethodNotAllowed},
		{"GET", "/", http.StatusNotFound},
		{"GET", "/blocklist.json/x", http.StatusNotFound},
	} {
		if got := get(c.method, c.path).Code; got != c.code {
			t.Errorf("%s %s: %d, want %d", c.method, c.path, got, c.code)
		}
	}
}

func TestBlocklistTruncate(t *testing.T) {
	now := freshBlocker(t)
	for i := range blocklistMax + 5 {
		ip := fmt.Sprintf("203.0.%d.%d", i/250, i%250+1)
		blk.m[ip] = &offender{until: now.Add(time.Duration(i+1) * time.Second), strikes: 1, event: "bad_cookie"}
	}
	rec := httptest.NewRecorder()
	serveBlocklist(rec, httptest.NewRequest("GET", "/blocklist.json", nil))
	var out struct{ Items []entry }
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Items) != blocklistMax {
		t.Fatalf("items %d", len(out.Items))
	}
	if out.Items[0].TTL != blocklistMax+5 || out.Items[len(out.Items)-1].TTL != 6 {
		t.Errorf("not longest ttl first: %d..%d", out.Items[0].TTL, out.Items[len(out.Items)-1].TTL)
	}
}

func TestStrictSNI(t *testing.T) {
	freshBlocker(t)
	defer func(old []string) { allowedHosts = old }(allowedHosts)
	cert := &tls.Certificate{}
	calls := 0
	get := strictSNI(func(*tls.ClientHelloInfo) (*tls.Certificate, error) { calls++; return cert, nil })

	allowedHosts = nil
	if c, err := get(&tls.ClientHelloInfo{}); c != cert || err != nil {
		t.Error("no ALLOWED_HOSTS should not check SNI")
	}
	allowedHosts = []string{"example.com"}
	for sni, ok := range map[string]bool{"example.com": true, "EXAMPLE.COM": true, "example.com.": true, "": false, "other.com": false, "203.0.113.1": false} {
		calls = 0
		c, err := get(&tls.ClientHelloInfo{ServerName: sni})
		if ok != (c == cert && err == nil && calls == 1) {
			t.Errorf("sni %q: cert=%v err=%v", sni, c != nil, err)
		}
		if !ok && (c != nil || calls != 0) {
			t.Errorf("sni %q: certificate returned", sni)
		}
	}
	if len(blk.m) != 0 {
		t.Error("SNI mismatch created an event")
	}
}

func TestServeFont(t *testing.T) {
	rec := httptest.NewRecorder()
	serveFont(rec, httptest.NewRequest("GET", "/__gate/h.woff2", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "font/woff2" {
		t.Errorf("Content-Type %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control %q", cc)
	}
	if len(headingFont) == 0 || !bytes.Equal(rec.Body.Bytes(), headingFont) {
		t.Error("body differs from embedded font")
	}
}

// main.go 讀取的環境變數名稱：os.Getenv 與包裝它的函式（第一個參數直接傳給 os.Getenv）的字串常數第一引數
func codeEnvVars(t *testing.T, src []byte) (names map[string]bool, helpers []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "main.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	isGetenv := func(c *ast.CallExpr) bool {
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Getenv" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "os"
	}
	wrap := map[string]bool{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Recv != nil || len(fd.Type.Params.List) == 0 || len(fd.Type.Params.List[0].Names) == 0 {
			continue
		}
		p := fd.Type.Params.List[0].Names[0].Name
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok && isGetenv(c) && len(c.Args) == 1 {
				if id, ok := c.Args[0].(*ast.Ident); ok && id.Name == p {
					wrap[fd.Name.Name] = true
				}
			}
			return true
		})
	}
	for h := range wrap {
		helpers = append(helpers, h)
	}
	sort.Strings(helpers)
	names = map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) == 0 {
			return true
		}
		id, isIdent := c.Fun.(*ast.Ident)
		if !isGetenv(c) && !(isIdent && wrap[id.Name]) {
			return true
		}
		if lit, ok := c.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if s, err := strconv.Unquote(lit.Value); err == nil {
				names[s] = true
			}
		}
		return true
	})
	return names, helpers
}

// README「## 設定」表格（到下一個標題為止）第一欄的變數名稱
func readmeEnvVars(readme string) map[string]bool {
	names := map[string]bool{}
	in := false
	nameRe := regexp.MustCompile("`([A-Z][A-Z0-9_]*)`")
	for _, line := range strings.Split(strings.ReplaceAll(readme, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "#") {
			in = strings.TrimSpace(line) == "## 設定"
			continue
		}
		if !in || !strings.HasPrefix(line, "| `") {
			continue
		}
		cell := strings.SplitN(line[1:], "|", 2)[0]
		for _, m := range nameRe.FindAllStringSubmatch(cell, -1) {
			names[m[1]] = true
		}
	}
	return names
}

// 兩邊的差異：程式有讀但 README 沒寫、README 有寫但程式沒讀
func envVarDrift(code, doc map[string]bool) (missing, extra []string) {
	// 不是 main.go 讀的、由 Go runtime 讀取的變數
	runtimeVars := map[string]bool{"GOMEMLIMIT": true}
	for k := range code {
		if !doc[k] {
			missing = append(missing, k)
		}
	}
	for k := range doc {
		if !code[k] && !runtimeVars[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return
}

func TestReadmeEnvVars(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	code, helpers := codeEnvVars(t, src)
	doc := readmeEnvVars(string(readme))
	if len(code) == 0 || len(doc) == 0 {
		t.Fatalf("解析不到變數：code=%v doc=%v", code, doc)
	}
	t.Logf("helpers=%v code=%d doc=%d", helpers, len(code), len(doc))
	missing, extra := envVarDrift(code, doc)
	if len(missing) > 0 {
		t.Errorf("main.go 有讀但 README 設定表沒列：%v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("README 設定表有列但 main.go 沒讀：%v", extra)
	}

	// 確認比對真的抓得到差異：把一列改名
	renamed := strings.Replace(string(readme), "| `LISTEN` |", "| `LISTEN_ADDR` |", 1)
	if renamed == string(readme) {
		t.Fatal("README 找不到 LISTEN 列")
	}
	missing, extra = envVarDrift(code, readmeEnvVars(renamed))
	if fmt.Sprint(missing, extra) != "[LISTEN] [LISTEN_ADDR]" {
		t.Errorf("改名後 missing=%v extra=%v", missing, extra)
	}
}
