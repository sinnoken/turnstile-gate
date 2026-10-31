// turnstile-gate: 單一執行檔的反向代理，前面加一道 Cloudflare Turnstile 驗證。
// 通過驗證 → 發 HMAC 簽章 cookie → 之後的請求直接轉發到上游（例如 DSM）。
// 確定不是真人的 IP（偽造 cookie、偽造或重複送 token）會被封鎖，清單可另開 listener 給路由器拉取。
package main

import (
	"cmp"
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
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"slices"
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
	// 允許的網域，逗號分隔；設定後其他 Host 一律 421，HTTPS 時 SNI 不符的握手也直接中斷
	allowedHosts []string
	// 封鎖清單 JSON 的監聽位址（只放內部位址）；沒設就不啟用
	blocklistListen string
	logLevel        = new(slog.LevelVar)
)

func loadConfig() error {
	var err error
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		if err := logLevel.UnmarshalText([]byte(v)); err != nil {
			return fmt.Errorf("bad LOG_LEVEL %q", v)
		}
	}
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
	blocklistListen = os.Getenv("BLOCKLIST_LISTEN")
	return nil
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))
	if err := loadConfig(); err != nil {
		fatal("config", err)
	}
	if insecure && serverName != "" {
		slog.Warn("UPSTREAM_SERVER_NAME 已設定，忽略 UPSTREAM_INSECURE", "server_name", serverName)
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
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure && serverName == "", ServerName: serverName},
			MaxIdleConnsPerHost: 32,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.Canceled) { // 用戶端自己中斷（關分頁、long-poll 被取消）
				slog.Debug("upstream", "err", err, "path", r.URL.Path)
				return
			}
			slog.Error("upstream", "err", err, "path", r.URL.Path)
			w.WriteHeader(http.StatusBadGateway)
		},
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           newHandler(proxy),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		// TLS 握手失敗（含嚴格 SNI 擋下的）等雜訊只在 debug 出現
		ErrorLog: log.New(serverLog{}, "", 0),
	}
	go blk.run()

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fatal("listen", err)
	}
	// TRUST_CF_HEADER 時 RemoteAddr 是 Cloudflare 節點，不能在 listener 層封鎖，改由 handler 回 403
	if !trustCF {
		ln = blockListener{ln, blk}
	}

	var bsrv *http.Server
	if blocklistListen != "" {
		bl, err := net.Listen("tcp", blocklistListen)
		if err != nil {
			fatal("blocklist listen", err)
		}
		bsrv = &http.Server{Handler: http.HandlerFunc(serveBlocklist), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		slog.Info("blocklist", "listen", blocklistListen)
		go func() {
			if err := bsrv.Serve(bl); err != http.ErrServerClosed {
				fatal("blocklist serve", err)
			}
		}()
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
		if bsrv != nil {
			bsrv.Shutdown(ctx)
		}
		srv.Shutdown(ctx)
		close(done)
	}()

	if certFile != "" && keyFile != "" {
		cl := &certLoader{}
		if _, err := cl.get(nil); err != nil {
			fatal("load cert", err)
		}
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: strictSNI(cl.get)}
		slog.Info("start", "mode", "https", "listen", listen, "upstream", upstream.String())
		err = srv.ServeTLS(ln, "", "")
	} else {
		slog.Info("start", "mode", "http", "listen", listen, "upstream", upstream.String(), "note", "no cert configured")
		err = srv.Serve(ln)
	}
	if err != http.ErrServerClosed {
		fatal("serve", err)
	}
	<-done
	slog.Info("shutdown")
}

func newHandler(proxy http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__gate", servePage)
	mux.HandleFunc("GET /__gate/h.woff2", serveFont)
	mux.HandleFunc("POST /__gate/verify", verify)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		st := cookieState(r)
		if st == cookieValid || (hasPrefix(r.URL.Path, bypass) && !hasDotDot(r.URL.Path)) {
			proxy.ServeHTTP(w, r)
			return
		}
		switch st {
		case cookieMalformed:
			if report(r, clientIP(r), "bad_cookie", "", nil) {
				w.Header().Set("Connection", "close")
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		case cookieBadSig, cookieExpired:
			// 通常是換了 GATE_KEY 或過期：清掉讓使用者重新驗證，不算事件
			http.SetCookie(w, gateCookie("", -1))
		}
		// 非瀏覽器導覽（XHR、API）直接 401，避免 JSON 請求收到 HTML
		if r.Method != http.MethodGet || !strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Error(w, "verification required", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/__gate?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		slog.Debug("request", "ip", ip, "method", r.Method, "host", r.Host, "path", r.URL.Path)
		// 觸發封鎖的 keep-alive 連線、或 TRUST_CF_HEADER 時（listener 層不封）
		if blk.blocked(ip) {
			w.Header().Set("Connection", "close")
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if !allowedHost(r.Host) {
			slog.Debug("misdirected", "ip", ip, "host", r.Host)
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
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
			slog.Error("reload cert failed, keep old", "err", err)
			return c.cert, nil
		}
		return nil, err
	}
	c.cert, c.mod = &crt, st.ModTime()
	slog.Info("certificate loaded")
	return c.cert, nil
}

var errSNI = errors.New("unknown server name")

// 嚴格 SNI：設了 ALLOWED_HOSTS 時，SNI 不在清單（含用 IP 連線、沒有 SNI）就不送出憑證。不算事件
func strictSNI(get func(*tls.ClientHelloInfo) (*tls.Certificate, error)) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if len(allowedHosts) > 0 && !allowedHost(hi.ServerName) {
			ip := ""
			if hi.Conn != nil {
				ip = addrIP(hi.Conn.RemoteAddr())
			}
			slog.Debug("sni rejected", "ip", ip, "sni", hi.ServerName)
			return nil, errSNI
		}
		return get(hi)
	}
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
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	page.Execute(w, map[string]any{
		"SiteKey": siteKey,
		"Next":    safeNext(r.URL.Query().Get("next")),
		"Err":     r.URL.Query().Has("err"),
	})
}

// ---------- 驗證 token、發 cookie ----------

// serverLog：http.Server 的錯誤日誌。TLS 握手失敗（掃描器、嚴格 SNI）是日常雜訊，記 debug；
// 其他（panic、Accept 錯誤、HTTP/2 錯誤）記 error。
type serverLog struct{}

func (serverLog) Write(p []byte) (int, error) {
	s := strings.TrimSpace(string(p))
	if strings.HasPrefix(s, "http: TLS handshake error") {
		slog.Debug(s)
	} else {
		slog.Error(s)
	}
	return len(p), nil
}

func verify(w http.ResponseWriter, r *http.Request) {
	// Turnstile token 約 2 KB，表單不需要更大
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		// 沒讀完的 body（使用者中途離開、連線中斷）不能當成空 token，否則會誤封
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	next := safeNext(r.PostFormValue("next"))
	token := r.PostFormValue("cf-turnstile-response")

	ip := clientIP(r)
	res := siteverify(token, ip, r.Host)
	if !res.ok {
		switch sig := res.signal(); {
		case sig != "":
			if report(r, ip, "verify_fail", sig, res.codes) {
				w.Header().Set("Connection", "close")
			}
		case res.err != nil:
			slog.Error("siteverify", "err", res.err, "ip", ip)
		default:
			slog.Error("siteverify", "errors", res.codes, "ip", ip)
		}
		http.Redirect(w, r, "/__gate?err=1&next="+url.QueryEscape(next), http.StatusSeeOther)
		return
	}

	exp := strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)
	http.SetCookie(w, gateCookie(exp+"."+sign(exp), int(ttl.Seconds())))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

var siteverifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

// codes 是 Cloudflare 的 error-codes，另加閘門自己判斷的 empty-token、hostname-mismatch；err 是連線或解碼錯誤
type svResult struct {
	ok    bool
	codes []string
	err   error
}

func siteverify(token, ip, host string) svResult {
	if token == "" {
		return svResult{codes: []string{"empty-token"}}
	}
	c := http.Client{Timeout: 8 * time.Second}
	resp, err := c.PostForm(siteverifyURL, url.Values{
		"secret": {secretKey}, "response": {token}, "remoteip": {ip},
	})
	if err != nil {
		return svResult{err: err}
	}
	defer resp.Body.Close()
	var res struct {
		Success  bool     `json:"success"`
		Hostname string   `json:"hostname"`
		Errors   []string `json:"error-codes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&res); err != nil {
		return svResult{err: err}
	}
	if !res.Success {
		if len(res.Errors) == 0 {
			res.Errors = []string{"unknown"}
		}
		return svResult{codes: res.Errors}
	}
	// token 必須是在本網域產生的
	if res.Hostname != "" && normHost(res.Hostname) != normHost(host) {
		return svResult{codes: []string{"hostname-mismatch"}}
	}
	return svResult{ok: true}
}

// strong：立即封鎖；weak：10 分鐘內第 2 次才封鎖；""：閘門設定或 Cloudflare 的問題，不算事件
func (s svResult) signal() string {
	if s.ok || s.err != nil {
		return ""
	}
	strong, weak := false, false
	for _, c := range s.codes {
		switch c {
		case "missing-input-secret", "invalid-input-secret", "internal-error":
			return ""
		case "empty-token", "hostname-mismatch", "invalid-input-response", "bad-request":
			strong = true
		case "timeout-or-duplicate":
			weak = true
		}
	}
	switch {
	case strong:
		return "strong"
	case weak:
		return "weak"
	}
	return ""
}

// ---------- cookie ----------

func sign(v string) string {
	m := hmac.New(sha256.New, gateKey)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))
}

func gateCookie(v string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     cookieName,
		Value:    v,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// 數值越大越寬鬆；多個同名 cookie 取最大值
type cookieStatus int

const (
	cookieNone cookieStatus = iota
	cookieMalformed
	cookieBadSig
	cookieExpired
	cookieValid
)

func (s cookieStatus) String() string {
	return [...]string{"none", "malformed", "badsig", "expired", "valid"}[s]
}

// 日後改 cookie 格式時，舊格式必須判為 badsig（清除、不算事件），否則所有人都會被當成 malformed 封鎖
func cookieState(r *http.Request) cookieStatus {
	st := cookieNone
	for _, c := range r.CookiesNamed(cookieName) {
		if c.Value != "" {
			st = max(st, parseCookie(c.Value))
		}
	}
	return st
}

func parseCookie(v string) cookieStatus {
	exp, sig, ok := strings.Cut(v, ".")
	if !ok || len(sig) != 64 {
		return cookieMalformed
	}
	t, err := strconv.ParseInt(exp, 10, 64)
	if err != nil {
		return cookieMalformed
	}
	if _, err := hex.DecodeString(sig); err != nil {
		return cookieMalformed
	}
	if !hmac.Equal([]byte(sig), []byte(sign(exp))) {
		return cookieBadSig
	}
	if time.Now().Unix() >= t {
		return cookieExpired
	}
	return cookieValid
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

// ---------- 封鎖 ----------

const (
	tableMax     = 50000
	weakWindow   = 10 * time.Minute
	strikeWindow = 7 * 24 * time.Hour
	sweepEvery   = 10 * time.Minute
	// RouterOS /tool/fetch output=user 讀回上限約 64 KB；每筆最長約 72 bytes，800 筆約 58 KB
	blocklistMax = 800
)

type offender struct {
	until    time.Time // 封鎖到期；零值 = 未封鎖
	strikes  int       // 7 天內被封鎖的次數
	lastHit  time.Time // 最後一次被封鎖（判斷 7 天視窗）
	failedAt time.Time // 最後一次 verify_fail（判斷 10 分鐘視窗）
	event    string    // 最後一次封鎖的事件，給封鎖清單
}

type blocker struct {
	mu       sync.Mutex
	m        map[string]*offender // key = IP 字串
	max      int
	now      func() time.Time
	fullTill time.Time // 表滿且全部在封鎖中：最早解封前不再掃描
}

var blk = newBlocker()

func newBlocker() *blocker {
	return &blocker{m: map[string]*offender{}, max: tableMax, now: time.Now}
}

func blockKey(ip string) (string, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

func (b *blocker) blocked(ip string) bool {
	k, ok := blockKey(ip)
	if !ok {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	o := b.m[k]
	return o != nil && o.until.After(b.now())
}

// 事件日誌由呼叫端記錄；回傳 true 表示此 IP 現在封鎖中
func (b *blocker) hit(ip, event, signal string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	k := a.String()
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	o := b.m[k]
	if o == nil {
		if len(b.m) >= b.max {
			if now.Before(b.fullTill) {
				return false
			}
			if !b.evict(now) {
				slog.Warn("table full", "ip", k, "entries", len(b.m), "until", b.fullTill)
				return false
			}
		}
		o = &offender{}
		b.m[k] = o
	}
	// 同時多條連線觸發時不重複加重
	if o.until.After(now) {
		return true
	}
	if event == "verify_fail" {
		prev := o.failedAt
		o.failedAt = now
		if signal == "weak" && (prev.IsZero() || now.Sub(prev) > weakWindow) {
			return false
		}
	}
	if !o.lastHit.IsZero() && now.Sub(o.lastHit) > strikeWindow {
		o.strikes = 0
	}
	o.strikes++
	o.lastHit = now
	d := blockFor(o.strikes)
	o.until, o.event = now.Add(d), event
	attrs := []any{"ip", k, "event", event}
	if signal != "" {
		attrs = append(attrs, "signal", signal)
	}
	slog.Warn("blocked", append(attrs, "strike", o.strikes, "duration", d.String())...)
	return true
}

func blockFor(strikes int) time.Duration {
	switch strikes {
	case 1:
		return time.Hour
	case 2:
		return 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// 表滿：刪一筆沒在封鎖、lastHit 最舊的項目；全部都在封鎖中就回 false。呼叫端持有鎖
func (b *blocker) evict(now time.Time) bool {
	var victim string
	var oldest, soonest time.Time
	for k, o := range b.m {
		if o.until.After(now) {
			if soonest.IsZero() || o.until.Before(soonest) {
				soonest = o.until
			}
			continue
		}
		if victim == "" || o.lastHit.Before(oldest) {
			victim, oldest = k, o.lastHit
		}
	}
	if victim == "" {
		b.fullTill = soonest
		return false
	}
	delete(b.m, victim)
	return true
}

// 刪除封鎖、累犯、verify_fail 紀錄都已過期的項目；回傳剩餘筆數與封鎖中筆數
func (b *blocker) sweep() (entries, blocked int) {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, o := range b.m {
		if !o.until.After(now) && now.Sub(o.lastHit) >= strikeWindow && now.Sub(o.failedAt) >= weakWindow {
			delete(b.m, k)
			continue
		}
		if o.until.After(now) {
			blocked++
		}
	}
	return len(b.m), blocked
}

func (b *blocker) run() {
	t := time.NewTicker(sweepEvery)
	for i := 1; ; i++ {
		<-t.C
		n, nb := b.sweep()
		if i%int(time.Hour/sweepEvery) == 0 {
			slog.Info("table", "entries", n, "blocked", nb)
		}
	}
}

type entry struct {
	IP     string `json:"ip"`
	TTL    int    `json:"ttl"`
	Event  string `json:"event"`
	Strike int    `json:"strike"`
}

// 目前封鎖中的 IPv4 與剩餘秒數（無條件進位）
func (b *blocker) list() []entry {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []entry{}
	for k, o := range b.m {
		if !o.until.After(now) {
			continue
		}
		if a, err := netip.ParseAddr(k); err != nil || !a.Is4() {
			continue
		}
		left := o.until.Sub(now)
		out = append(out, entry{k, int((left + time.Second - 1) / time.Second), o.event, o.strikes})
	}
	return out
}

// 記錄事件並交給封鎖表；回傳 true 表示此 IP 現在封鎖中
func report(r *http.Request, ip, event, signal string, codes []string) bool {
	ua := r.UserAgent()
	if len(ua) > 256 {
		ua = ua[:256]
	}
	attrs := []any{"event", event}
	if signal != "" {
		attrs = append(attrs, "signal", signal)
	}
	attrs = append(attrs, "ip", ip, "host", r.Host, "ua", ua)
	if codes != nil {
		attrs = append(attrs, "errors", codes)
	}
	slog.Info("event", attrs...)
	return blk.hit(ip, event, signal)
}

type blockListener struct {
	net.Listener
	b *blocker
}

// 封鎖中的來源在 TLS 握手前直接關閉
func (l blockListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ip := addrIP(c.RemoteAddr()); ip != "" && l.b.blocked(ip) {
			slog.Debug("dropped", "ip", ip)
			c.Close()
			continue
		}
		return c, nil
	}
}

func addrIP(a net.Addr) string {
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return ""
	}
	return ap.Addr().Unmap().String()
}

func serveBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/blocklist.json" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	items := blk.list()
	slices.SortFunc(items, func(a, b entry) int { return cmp.Compare(b.TTL, a.TTL) })
	if len(items) > blocklistMax {
		slog.Warn("blocklist truncated", "items", len(items), "max", blocklistMax)
		items = items[:blocklistMax]
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(struct {
		Generated string  `json:"generated"`
		Items     []entry `json:"items"`
	}{blk.now().UTC().Format(time.RFC3339), items})
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

// 沒設 ALLOWED_HOSTS 時不檢查（Host 與 SNI 共用）
func allowedHost(h string) bool {
	if len(allowedHosts) == 0 {
		return true
	}
	h = normHost(h)
	for _, a := range allowedHosts {
		if h == normHost(a) {
			return true
		}
	}
	return false
}

// 去掉 port 與結尾的 .（ninja.example.me. 是合法寫法），轉小寫
func normHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(stripPort(h), "."))
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
