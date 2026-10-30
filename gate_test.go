package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

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
		"ninja.example.me":      true,
		"NINJA.example.me:8443": true,
		"[::1]:8443":            false,
		"[::1]":                 false,
		"other.example.me":      false,
		"192.168.1.1":           false,
	}
	for in, want := range cases {
		if got := allowedHost(in); got != want {
			t.Errorf("allowedHost(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidCookie(t *testing.T) {
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

	cases := []struct {
		name, val string
		want      bool
	}{
		{"valid", good, true},
		{"expired", past + "." + sign(past), false},
		{"tampered sig", tampered, false},
		{"tampered exp", future + "1." + sign(future), false},
		{"no dot", future + sign(future), false},
		{"non-numeric", "abc." + sign("abc"), false},
		{"empty", "", false},
		{"other key", otherKey, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: cookieName, Value: c.val})
		if got := validCookie(r); got != c.want {
			t.Errorf("%s: validCookie = %v, want %v", c.name, got, c.want)
		}
	}
	if validCookie(httptest.NewRequest("GET", "/", nil)) {
		t.Error("missing cookie accepted")
	}
}

func postVerify(body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/__gate/verify", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	verify(rec, r)
	return rec
}

// 超過上限，在呼叫 siteverify 之前就回 413（不會連線）
func TestVerifyBodyLimit(t *testing.T) {
	rec := postVerify("next=/&cf-turnstile-response=" + strings.Repeat("a", 5000))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413", rec.Code)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("cookie set")
	}
}

// 沒有 token 時 siteverify 不會連線，直接導回驗證頁
func TestVerifyNoToken(t *testing.T) {
	rec := postVerify("next=/x")
	want := "/__gate?err=1&next=" + url.QueryEscape("/x")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Errorf("got %d %q, want 303 %q", rec.Code, rec.Header().Get("Location"), want)
	}
	if rec.Header().Get("Set-Cookie") != "" {
		t.Error("cookie set without verification")
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
