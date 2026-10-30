// turnstile-gate: 單一執行檔的反向代理，前面加一道 Cloudflare Turnstile 驗證。
// 通過驗證 → 發 HMAC 簽章 cookie → 之後的請求直接轉發到上游（例如 DSM）。
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const cookieName = "__gate"

// 設定值由 loadConfig 從環境變數讀入（測試時直接指定）
var (
	siteKey   string
	secretKey string
	gateKey   []byte   // 隨機長字串，用來簽 cookie
	upstream  *url.URL // 例：https://192.168.1.10:5001
	listen    string
	// 匯入的憑證（PEM）。兩個都有就啟用 HTTPS；檔案更新後會自動重新載入
	certFile, keyFile string
	// 只有在 Cloudflare 後面時才設 1；直接對外時這個標頭可被偽造
	trustCF bool
	ttl     time.Duration
	// 不需驗證的路徑前綴（給手機 App 等），逗號分隔；預設全部都要驗證
	bypass []string
	// 上游是自簽憑證（DSM 預設）時設 1
	insecure bool
	// 以 IP 連上游、但憑證是網域的（例如 DSM 的 Let's Encrypt）時，設成該網域來驗證憑證；設定後忽略 UPSTREAM_INSECURE
	serverName string
	// 允許的網域，逗號分隔；設定後其他 Host（例如直接打 IP 的掃描器）一律 404
	allowedHosts []string
)

func loadConfig() error {
	var err error
	if siteKey, err = needEnv("TURNSTILE_SITEKEY"); err != nil {
		return err
	}
	if secretKey, err = needEnv("TURNSTILE_SECRET"); err != nil {
		return err
	}
	gk, err := needEnv("GATE_KEY")
	if err != nil {
		return err
	}
	gateKey = []byte(gk)
	up, err := needEnv("UPSTREAM")
	if err != nil {
		return err
	}
	if upstream, err = parseUpstream(up); err != nil {
		return err
	}
	listen = envOr("LISTEN", ":8443")
	certFile, keyFile = certPaths()
	trustCF = os.Getenv("TRUST_CF_HEADER") == "1"
	ttl = time.Duration(envInt("SESSION_HOURS", 12)) * time.Hour
	bypass = splitList(os.Getenv("BYPASS_PREFIXES"))
	insecure = os.Getenv("UPSTREAM_INSECURE") == "1"
	serverName = os.Getenv("UPSTREAM_SERVER_NAME")
	allowedHosts = splitList(os.Getenv("ALLOWED_HOSTS"))
	return nil
}

func main() {
	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}
	if insecure && serverName != "" {
		log.Printf("UPSTREAM_SERVER_NAME=%s 已設定，忽略 UPSTREAM_INSECURE", serverName)
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(upstream)
			r.Out.Host = r.In.Host
			// DSM 信任閘門轉來的 IP 標頭；用戶端自帶的同類標頭一律刪掉，避免偽造 IP 繞過 DSM 的自動封鎖
			for _, h := range []string{"Forwarded", "X-Client-IP", "True-Client-IP", "X-Cluster-Client-IP", "CF-Connecting-IP", "X-Original-Forwarded-For"} {
				r.Out.Header.Del(h)
			}
			ip := clientIP(r.In)
			r.Out.Header.Set("X-Real-IP", ip)
			r.Out.Header.Set("X-Forwarded-For", ip)
			r.Out.Header.Set("X-Forwarded-Proto", "https")
			r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
			stripGateCookie(r.Out)
		},
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure && serverName == "", ServerName: serverName},
			MaxIdleConnsPerHost: 32,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /__gate", servePage)
	mux.HandleFunc("GET /__gate/h.woff2", serveFont)
	mux.HandleFunc("POST /__gate/verify", verify)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if validCookie(r) || (hasPrefix(r.URL.Path, bypass) && !hasDotDot(r.URL.Path)) {
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
		Addr: listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !allowedHost(r.Host) {
				http.NotFound(w, r)
				return
			}
			mux.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	// 停止容器時會收到 SIGTERM。容器內的 PID 1 不會被訊號的預設動作終止，
	// Go 最後只能以 exit status 2 結束，所以自己處理：等進行中的請求結束後正常退出
	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		close(done)
	}()

	var err error
	if certFile != "" && keyFile != "" {
		cl := &certLoader{}
		if _, err := cl.get(nil); err != nil {
			log.Fatalf("load cert: %v", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: cl.get}
		log.Printf("HTTPS on %s → %s", listen, upstream)
		err = srv.ListenAndServeTLS("", "")
	} else {
		log.Printf("HTTP on %s → %s (no cert configured)", listen, upstream)
		err = srv.ListenAndServe()
	}
	if err != http.ErrServerClosed {
		log.Fatal(err)
	}
	<-done
	log.Printf("shutdown")
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
<title>安全確認</title>
<style>
@font-face{font-family:"Gate Heading";font-weight:800;font-display:swap;src:url(/__gate/h.woff2) format("woff2")}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px;font-family:system-ui,"PingFang TC","Microsoft JhengHei","Noto Sans TC",sans-serif;color:#2d3b2a;background:#e3e0eb radial-gradient(#f2f1f6 22%,transparent 23%);background-size:22px 22px}
main{width:100%;max-width:440px;display:flex;flex-direction:column;align-items:center;gap:24px;text-align:center}
p{margin:0}
.eb{font-size:18px;font-weight:700;letter-spacing:.08em;color:#4a7f69}
.s{color:#d75351}.s::before{content:"★"}
h1{margin:0;padding:14px 28px;border:3px solid #382d39;border-radius:20px;box-shadow:5px 5px 0 #382d39;background:#fff;color:#2d3b2a;font:800 36px/1.2 "Gate Heading",system-ui,sans-serif}
.er{width:100%;padding:12px 24px;background:#444;color:#fff;font-size:15px;font-weight:700}
section{width:100%;padding:24px;border:6px solid #64af91;background:#fff;display:flex;flex-direction:column;align-items:center;gap:16px}
#st{font-size:15px;line-height:1.75}
.fn{font-size:12px;line-height:1.6;color:#3b3b3d}
@media(prefers-color-scheme:dark){
body{color:#fff;background:linear-gradient(#7d34b3 1px,transparent 1px),linear-gradient(90deg,#7d34b3 1px,transparent 1px) #6f23a7;background-size:32px 32px}
.eb{color:#0adaca}.s{color:#f997d2}.s::before{content:"☆"}
h1{background:#fdbae6;border-color:#340d50;box-shadow:5px 5px 0 #340d50;color:#340d50}
section{background:#340d50;border-color:#340d50}
.fn{color:#e0d0f0}
}
</style></head><body><main>
<p class="eb"><span class="s" aria-hidden="true"></span> SECURITY CHECK <span class="s" aria-hidden="true"></span></p>
<h1>請完成驗證以繼續！</h1>
{{if .Err}}<p class="er" role="alert">這次沒有確認成功，請再試一次！</p>{{end}}
<section>
<noscript><p>請開啟 JavaScript，才能完成驗證。</p></noscript>
<form id="f" method="post" action="/__gate/verify">
<input type="hidden" name="next" value="{{.Next}}">
<div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="ok"></div>
</form>
<p id="st">驗證元件載入中…</p>
</section>
<p class="fn">{{if .Err}}一直失敗的話，請關閉廣告封鎖或換個瀏覽器。{{else}}一段時間內不用再驗證。需要啟用 Cookie 與 JavaScript。{{end}}</p>
</main>
<script>
function say(t){document.getElementById("st").textContent=t}
function loaded(){say("確認你不是機器人後，就會自動前往網站。")}
function ok(){say("確認完成！正在前往網站…");document.getElementById("f").submit()}
</script>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=loaded" defer></script>
</body></html>`))

// 只含標題「請完成驗證以繼續！」這幾個字的子集（Chiron GoRound TC ExtraBold，授權見 fonts/OFL.txt）。
// 改標題文字就要重新產生，例如用 Google Fonts css2 的 text= 參數或 fonttools 的 pyftsubset
//
//go:embed fonts/gate-heading.woff2
var headingFont []byte

func serveFont(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(headingFont)
}

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
	// Turnstile token 約 2 KB，表單不需要更大
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	next := safeNext(r.PostFormValue("next"))
	token := r.PostFormValue("cf-turnstile-response")

	ip := clientIP(r)
	ok, err := siteverify(token, ip, r.Host)
	if !ok {
		// 一行記下 IP 與原因（Cloudflare 的 error-codes、連線錯誤或沒有 token），方便日後統計
		reason := "empty token"
		if err != nil {
			reason = err.Error()
		}
		log.Printf("verify failed ip=%s reason=%q", ip, reason)
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

// 只允許站內相對路徑，防止 open redirect。
// http.Redirect 會再做 path.Clean（/./\x → /\x），所以先照同樣方式整理、再檢查一次並回傳整理後的值；
// 瀏覽器會忽略網址裡的 TAB、換行（/<TAB>/x 等於 //x），含控制字元一律拒絕
func safeNext(n string) string {
	bad := func(s string) bool {
		return !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\")
	}
	if bad(n) || strings.ContainsFunc(n, func(r rune) bool { return r < ' ' || r == 0x7f }) {
		return "/"
	}
	p, q := n, ""
	if i := strings.Index(n, "?"); i >= 0 {
		p, q = n[:i], n[i:]
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && !strings.HasSuffix(c, "/") {
		c += "/"
	}
	if bad(c) {
		return "/"
	}
	return c + q
}

func hasPrefix(p string, list []string) bool {
	for _, x := range list {
		if strings.HasPrefix(p, x) {
			return true
		}
	}
	return false
}

// ServeMux 不會清理 %2e%2e、..%2f 這類編碼過的 ..，原樣轉給上游後可能被正規化成前綴以外的路徑
func hasDotDot(p string) bool {
	for _, s := range strings.FieldsFunc(p, func(c rune) bool { return c == '/' || c == '\\' }) {
		if s == ".." {
			return true
		}
	}
	return false
}

// CERT_FILE、KEY_FILE 都沒設時，若掛載了 /cert/fullchain.pem 與 /cert/privkey.pem 就直接使用
func certPaths() (string, string) {
	c, k := os.Getenv("CERT_FILE"), os.Getenv("KEY_FILE")
	if c != "" || k != "" {
		return c, k
	}
	const dc, dk = "/cert/fullchain.pem", "/cert/privkey.pem"
	if _, err := os.Stat(dc); err != nil {
		return "", ""
	}
	if _, err := os.Stat(dk); err != nil {
		return "", ""
	}
	return dc, dk
}

// 沒設 ALLOWED_HOSTS 時不檢查；比對時去掉 port、不分大小寫
func allowedHost(h string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	h = stripPort(h)
	for _, a := range allowedHosts {
		if strings.EqualFold(h, a) {
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

func needEnv(k string) (string, error) {
	v := os.Getenv(k)
	if v == "" {
		return "", fmt.Errorf("missing env %s", k)
	}
	return v, nil
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

func parseUpstream(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("bad UPSTREAM %q", s)
	}
	return u, nil
}
