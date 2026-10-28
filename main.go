// turnstile-gate: 單一執行檔的反向代理，前面加一道 Cloudflare Turnstile 驗證。
// 通過驗證 → 發 HMAC 簽章 cookie → 之後的請求直接轉發到上游（例如 DSM）。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cookieName = "__gate"

var (
	siteKey   = mustEnv("TURNSTILE_SITEKEY")
	secretKey = mustEnv("TURNSTILE_SECRET")
	gateKey   = []byte(mustEnv("GATE_KEY")) // 隨機長字串，用來簽 cookie
	upstream  = mustURL(mustEnv("UPSTREAM")) // 例：https://192.168.1.10:5001
	listen    = envOr("LISTEN", ":8443")
	// 匯入的憑證（PEM）。兩個都設就啟用 HTTPS；檔案更新後會自動重新載入
	certFile = os.Getenv("CERT_FILE")
	keyFile  = os.Getenv("KEY_FILE")
	// 只有在 Cloudflare 後面時才設 1；直接對外時這個標頭可被偽造
	trustCF = os.Getenv("TRUST_CF_HEADER") == "1"
	ttl       = time.Duration(envInt("SESSION_HOURS", 12)) * time.Hour
	// 不需驗證的路徑前綴（給手機 App 等），逗號分隔；預設全部都要驗證
	bypass = splitList(os.Getenv("BYPASS_PREFIXES"))
	// 上游是自簽憑證（DSM 預設）時設 1
	insecure = os.Getenv("UPSTREAM_INSECURE") == "1"
)

func main() {
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = r.In.Host
			ip := clientIP(r.In)
			r.Out.Header.Set("X-Real-IP", ip)
			r.Out.Header.Set("X-Forwarded-For", ip)
			r.Out.Header.Set("X-Forwarded-Proto", "https")
			r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
			stripGateCookie(r.Out)
		},
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
			MaxIdleConnsPerHost: 32,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /__gate", servePage)
	mux.HandleFunc("POST /__gate/verify", verify)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if validCookie(r) || hasPrefix(r.URL.Path, bypass) {
			proxy.ServeHTTP(w, r)
			return
		}
		// 非瀏覽器導覽（XHR、API）直接 401，避免 JSON 請求收到 HTML
		if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Error(w, "verification required", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/__gate?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	if certFile != "" && keyFile != "" {
		cl := &certLoader{}
		if _, err := cl.get(nil); err != nil {
			log.Fatalf("load cert: %v", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cl.get}
		log.Printf("HTTPS on %s → %s", listen, upstream)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}
	log.Printf("HTTP on %s → %s (no cert configured)", listen, upstream)
	log.Fatal(srv.ListenAndServe())
}

// ---------- 憑證：檔案有變動就重新載入（每分鐘最多檢查一次） ----------

type certLoader struct {
	mu      sync.Mutex
	cert    *tls.Certificate
	mod     time.Time
	checked time.Time
}

func (c *certLoader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cert != nil && time.Since(c.checked) < time.Minute {
		return c.cert, nil
	}
	c.checked = time.Now()
	st, err := os.Stat(certFile)
	if err != nil {
		if c.cert != nil {
			return c.cert, nil
		}
		return nil, err
	}
	if c.cert != nil && st.ModTime().Equal(c.mod) {
		return c.cert, nil
	}
	crt, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if c.cert != nil {
			log.Printf("reload cert failed, keep old: %v", err)
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.mod = &crt, st.ModTime()
	log.Printf("certificate loaded")
	return c.cert, nil
}

// ---------- 驗證頁 ----------

var page = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>驗證中</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#f4f4f5;color:#18181b}
@media(prefers-color-scheme:dark){body{background:#18181b;color:#e4e4e7}}
main{text-align:center;padding:16px}
</style></head><body><main>
<p>請完成驗證以繼續</p>
<form id="f" method="post" action="/__gate/verify">
<input type="hidden" name="next" value="{{.Next}}">
<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="ok"></div>
</form>
{{if .Err}}<p style="color:#dc2626">驗證失敗，請再試一次</p>{{end}}
<script>function ok(){document.getElementById("f").submit()}</script>
</main></body></html>`))

func servePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	page.Execute(w, map[string]any{
		"SiteKey": siteKey,
		"Next":    safeNext(r.URL.Query().Get("next")),
		"Err":     r.URL.Query().Has("err"),
	})
}

// ---------- 驗證 token、發 cookie ----------

func verify(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	next := safeNext(r.PostFormValue("next"))
	token := r.PostFormValue("cf-turnstile-response")

	ok, err := siteverify(token, clientIP(r), r.Host)
	if err != nil {
		log.Printf("siteverify error: %v", err)
	}
	if !ok {
		log.Printf("verify failed ip=%s", clientIP(r))
		http.Redirect(w, r, "/__gate?err=1&next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}

	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    exp + "." + sign(exp),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func siteverify(token, ip, host string) (bool, error) {
	if token == "" {
		return false, nil
	}
	c := http.Client{Timeout: 8 * time.Second}
	resp, err := c.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", url.Values{
		"secret": {secretKey}, "response": {token}, "remoteip": {ip},
	})
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var res struct {
		Success  bool     `json:"success"`
		Hostname string   `json:"hostname"`
		Errors   []string `json:"error-codes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return false, err
	}
	if !res.Success {
		return false, fmt.Errorf("rejected: %v", res.Errors)
	}
	// token 必須是在本網域產生的
	if res.Hostname != "" && !strings.EqualFold(res.Hostname, stripPort(host)) {
		return false, fmt.Errorf("hostname mismatch: %s", res.Hostname)
	}
	return true, nil
}

// ---------- cookie ----------

func sign(v string) string {
	m := hmac.New(sha256.New, gateKey)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func validCookie(r *http.Request) bool {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	exp, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(sign(exp))) {
		return false
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && time.Now().Unix() < t
}

// 不把閘門 cookie 傳給上游
func stripGateCookie(r *http.Request) {
	cs := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cs {
		if c.Name != cookieName {
			r.AddCookie(c)
		}
	}
}

// ---------- 小工具 ----------

func clientIP(r *http.Request) string {
	if trustCF {
		if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
			return ip
		}
	}
	h := r.RemoteAddr
	if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	return strings.Trim(h, "[]")
}

// 只允許站內相對路徑，防止 open redirect
func safeNext(n string) string {
	if !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") {
		return "/"
	}
	return n
}

func hasPrefix(p string, list []string) bool {
	for _, x := range list {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

func stripPort(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("missing env %s", k)
	}
	return v
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func envInt(k string, d int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil && n > 0 {
		return n
	}
	return d
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		log.Fatalf("bad UPSTREAM %q", s)
	}
	return u
}
