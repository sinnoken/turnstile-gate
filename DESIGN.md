# 設計文件：turnstile-gate 封鎖機制與強化

接下來開發的依據。讀完就能開工。

## 0. 進度（2026-10-30）

| 狀態 | 項目 |
|:-:|---|
| ✅ | F6／§3.6 `UPSTREAM_SERVER_NAME`（`a79bdd2`）；`.rsc` 加 `domain`、刪 `UPSTREAM_INSECURE`；compose 改用 `UPSTREAM_SERVER_NAME` |
| ✅ | §3.8／compose 加 `ALLOWED_HOSTS`；`GOMEMLIMIT=48MiB` 改為 Dockerfile 的 `ENV` 預設；`go.mod` 改 `go 1.27` |
| ✅ | 預設值：`CERT_FILE`／`KEY_FILE` 都沒設時自動使用 `/cert/fullchain.pem`、`/cert/privkey.pem`（存在才用）；`.rsc` 與 compose 拿掉與預設值相同的設定 |
| ✅ | §3.6 第一層：body 上限（4 KB → 413）、header 上限（64 KB）、`loadConfig`、`gate_test.go`（現有函式）、CI 每週重建與 `go test -race`／`govulncheck` |
| ⚠️ | `ALLOWED_HOSTS` 的 Host 檢查已實作（不符回 `404`，`allowedHost()`），但還沒有 `bad_host` 事件與封鎖，等封鎖機制接上 |
| 🟡 | §3.6 第二層（建議）：嚴格 SNI、上游逾時、驗證頁三個安全標頭、action 釘選 SHA |
| ❌ | 封鎖機制 F1～F5、slog、`docs/blocking.md`、`CHANGES-blocking.md`、U6 |

本文件以外已完成（安全掃描與部署修正）：`safeNext` 先整理路徑再檢查（open redirect）、`BYPASS_PREFIXES` 不放行含 `..` 的路徑、SIGTERM 正常關機、`.rsc` 的 `gateKey` 留空自動產生、RouterOS 7.24+ 語法、從 GHCR 拉映像與 `repull` 更新、驗證頁改用 Idol Live Kit 視覺（嵌入 5 KB 標題字型子集 `fonts/gate-heading.woff2`）。

§3.6 依「必要性」分三層（2026-10-30 檢討）：第一層有實際風險或是安全修改程式的前提；第二層便宜、效益實在但不急；HSTS、完整 CSP、`__Host-` cookie、刪上游 `Server` 標頭對本部署屬理論風險，移到 §8。

---

## 1. 背景與限制

```
網際網路 ─443─→ MikroTik RB5009（RouterOS v7，dst-nat）
                   └→ 容器 turnstile-gate 172.17.0.2:8443（TLS + Turnstile + HMAC cookie + 封鎖）
                         └─HTTPS─→ Synology DSM（內網 NAS:5001）
```

- 家用環境，容器跑在 RB5009（arm64）上，記憶體與儲存都有限。
- DSM 網域使用 Synology DDNS：`ninja218j.myds.me`（D2 已確定）。
- **閘門直接對外**，不經過 Cloudflare 代理或 Tunnel。只有 Turnstile 會用到 Cloudflare。
- 憑證來自 DSM 的 Let's Encrypt，由 DSM 排程推送到路由器。
- 使用者偏好：**輕量、精簡、有效**；不為理論風險增加複雜度；重視實際數據。
- 已定案的判斷：
  - Turnstile 只擋 bot，不負責身分驗證。身分驗證交給 DSM 的密碼與 2FA。
  - **不處理 IPv6**。實際紀錄中 IPv6 流量極少。
  - 不用 CrowdSec、Anubis、ALTCHA、AbuseIPDB。
  - 只封鎖「確定不是真人」的 IP，封鎖 1 小時起跳。
- 文件一律用 **繁體中文**（台灣用語）。

### 不要做的事

- 不要加入「真人也會觸發」的事件（例如沒有 cookie 的請求）。
- 不要讓容器拿到 RouterOS 的 API 帳密（RouterOS 無法只開放 address-list）。
- 不要把 DSM 的 80、5000、5001 直接轉發到外部，會繞過閘門。
- 不要在直接對外時預設開啟 `TRUST_CF_HEADER`，會讓攻擊者偽造來源 IP。
- 不要引入第三方 Go 套件；維持標準函式庫、單一執行檔。（CI 用的 `govulncheck` 是工具，不是相依套件，可以用。）
- 不要為 IPv6 加任何機制。

## 2. 需求

### 2.1 功能需求

| # | 需求 |
|---|---|
| F1 | 只有三種事件：`bad_host`、`bad_cookie`、`verify_fail`。沒有 cookie 的 API、favicon、DSM 背景請求一律不算事件 |
| F2 | 觸發封鎖的 IP，在 listener 層直接關閉連線，不做 TLS 握手 |
| F3 | 累犯加重：7 天內第 1 次封 1 小時、第 2 次封 24 小時、第 3 次以上封 7 天 |
| F4 | 換 `GATE_KEY` 後，舊 cookie 只會讓使用者重新驗證一次，不會被封鎖 |
| F5 | 私有、loopback、link-local IP 永不封鎖 |
| F6 | 上游可以用內網 IP 連線，同時用網域名稱驗證 DSM 憑證（✅ 已完成） |

### 2.2 非功能需求

| 項目 | 目標 |
|---|---|
| 記憶體 | 容器設 `GOMEMLIMIT=48MiB`；封鎖表上限 50,000 筆 ≈ 5 MB 以內 |
| 日誌量 | 被掃描時不洗掉 RouterOS `/log`：預設只記錄事件、封鎖、錯誤 |
| 程式量 | 封鎖相關 Go 程式約 100 行，維持單一 `main.go` |
| 可測試性 | `go test` 不需要設定任何環境變數 |
| 狀態 | 封鎖表只存在記憶體，重啟即清空（可接受） |

## 3. 設計

### 3.1 決策 D1：封鎖在閘門內做（方案 A）

| | **A. 閘門自己封鎖（採用）** | B. 通知路由器 |
|---|---|---|
| 做法 | 封鎖表放在記憶體，自訂 `net.Listener` 在 `Accept()` 時直接 `Close()` | 閘門提供 `/events`，RouterOS 定期拉取寫進 address-list，raw 規則丟棄 |
| 程式量 | Go 約 100 行 | Go 約 60 行 + RouterOS 腳本約 50 行 |
| 容易壞的地方 | 幾乎沒有 | 防火牆規則、腳本解析、RouterOS 版本差異 |
| 累犯加重 | 一個 map 就能做 | RouterOS 腳本很難做 |
| 效果差異 | 封包仍會到達容器，但只花一次 TCP accept + close 的成本 | 封包在路由器就丟棄 |

採用 A 的理由：路由器已經有 `connection-limit` 與 `dst-limit` 擋掉大量連線，剩下的連線由閘門 accept 後立即 close，成本極低；B 多出的部分（腳本、防火牆、版本差異）全是會壞的地方，換來的只有「封包少走一跳」。

> 使用者原本的想法是「通知路由器，由路由器處理」。如果之後真的要改成 B，封鎖表的資料結構不變，只要多一個 `/events` 端點與 RouterOS 腳本，A 的程式不會白做。

### 3.2 請求流程

```
TCP 連線
  │
  ▼
blockListener.Accept()  ── 來源 IP 封鎖中？──是──→ Close()（debug 層級才記錄）
  │否
  ▼
TLS 握手（certLoader 熱更新）── 設了 ALLOWED_HOSTS 且 SNI 不在清單 ──→ 中斷握手（嚴格 SNI，事件 bad_host）
  │
  ▼
handler
  ├─ 來源 IP 封鎖中？（keep-alive 連線、TRUST_CF_HEADER 時）──是──→ 403 + Connection: close
  ├─ Host 不在 ALLOWED_HOSTS ───────→ 事件 bad_host → 封鎖 → 404
  ├─ GET /__gate ─────────────────→ 驗證頁
  ├─ POST /__gate/verify ─────────→ body ≤ 4KB → siteverify
  │     ├─ 通過 ──────────────→ 發 cookie → 導回 next
  │     ├─ token 被判定無效 ───→ 事件 verify_fail（10 分鐘內第 2 次才封鎖）→ 驗證頁 ?err=1
  │     └─ 連線錯誤、secret 錯誤、internal-error → 只記錄錯誤，不算事件
  └─ 其他路徑：cookieState()
        ├─ valid ─────────────→ 轉發上游
        ├─ BYPASS_PREFIXES ───→ 轉發上游
        ├─ malformed ─────────→ 事件 bad_cookie → 封鎖 → 403
        ├─ badsig / expired ──→ 清除 cookie（不算事件）┐
        └─ none ──────────────────────────────────────┴→ 瀏覽器導覽：導向驗證頁
                                                          其他請求：401
```

### 3.3 事件定義

| 事件 | 觸發條件 | 處理 | 為什麼真人不會觸發 |
|---|---|---|---|
| `bad_host` | 設定了 `ALLOWED_HOSTS`，且 TLS 的 SNI 或 `Host`（去掉 port、不分大小寫）不在清單內 | 立即封鎖；SNI 不符時中斷握手，`Host` 不符時回 `404` | 真人只會用網域連線；直接打 IP 的是掃描器 |
| `bad_cookie` | `__gate` cookie 格式錯誤：沒有 `.`、到期時間不是數字、簽章不是 64 字元 hex | 立即封鎖，回 `403` | 閘門自己發的 cookie 格式永遠正確，換金鑰也不會改變格式 |
| `verify_fail` | siteverify 回 `success=false`，且錯誤碼不是 `internal-error` 或 `*-secret`；或 token 為空；或 hostname 不符 | 10 分鐘內第 1 次只記錄，第 2 次封鎖 | 重新整理、按上一頁偶爾造成一次 `timeout-or-duplicate`，不會連續發生 |

**cookie 狀態**（取代 `validCookie()`）：

| 狀態 | 條件 | 處理 |
|---|---|---|
| `none` | 沒有 cookie | 導向驗證頁或 401 |
| `valid` | 格式正確、簽章正確、未過期 | 轉發 |
| `expired` | 格式、簽章正確，但已過期 | 清除 cookie，導向驗證頁或 401 |
| `badsig` | 格式正確，簽章不符（通常是換了 `GATE_KEY`） | 清除 cookie（`Max-Age=-1`），導向驗證頁或 401，**不算事件** |
| `malformed` | 格式錯誤 | `bad_cookie` 事件 |

不在 cookie 裡加金鑰版本號：`badsig` 已經不算事件，版本號沒有額外好處。

### 3.4 封鎖表資料模型

```go
type offender struct {
	until    time.Time // 封鎖到期；零值 = 未封鎖
	strikes  int       // 7 天內被封鎖的次數
	lastHit  time.Time // 最後一次被封鎖的時間（判斷 7 天視窗）
	failedAt time.Time // 最後一次 verify_fail（判斷 10 分鐘視窗）
}

type blocker struct {
	mu sync.Mutex
	m  map[string]*offender // key = IP 字串
}
```

| 方法 | 行為 |
|---|---|
| `blocked(ip) bool` | `until` 在未來就回 true |
| `hit(ip, event)` | 私有 IP 直接回傳；`verify_fail` 先看 `failedAt` 是否在 10 分鐘內，不是就只更新 `failedAt`；其他情況封鎖：`lastHit` 超過 7 天就把 `strikes` 歸零，`strikes++`，依次數決定時長，記錄 `blocked` 日誌 |
| `sweep()` | 每 10 分鐘一次：刪除 `until`、`lastHit + 7d`、`failedAt + 10m` 都已過期的項目 |

封鎖時長：

| 7 天內第幾次 | 時長 |
|:-:|---|
| 1 | 1 小時 |
| 2 | 24 小時 |
| ≥ 3 | 7 天 |

- **上限 50,000 筆**：滿了就不再新增 IP（已存在的照常更新）。以每筆約 100 bytes 估算約 5 MB，在 48 MiB 內。
- **私有 IP 判斷**：`netip.Addr` 的 `IsPrivate() || IsLoopback() || IsLinkLocalUnicast()`。私有 IP 的事件照樣記錄日誌，只是不封鎖。
- 不提供可調整的門檻與時長環境變數，數值寫死在常數。需要時再加。

### 3.5 listener 層封鎖

```go
type blockListener struct {
	net.Listener
	b *blocker
}

func (l blockListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if ap, e := netip.ParseAddrPort(c.RemoteAddr().String()); e == nil && l.b.blocked(ap.Addr().Unmap().String()) {
			c.Close()
			continue
		}
		return c, nil
	}
}
```

- 啟動改為 `net.Listen` → 包上 `blockListener` → `srv.ServeTLS(ln, "", "")` 或 `srv.Serve(ln)`。
- **`TRUST_CF_HEADER=1` 時不包 listener**：此時 `RemoteAddr` 是 Cloudflare 節點，封鎖它等於封鎖所有人。改由 handler 用 `clientIP()` 檢查並回 `403`。
- handler 內也檢查一次，處理「觸發封鎖的那條 keep-alive 連線」：回 `403` 並加 `Connection: close`。

### 3.6 其他強化

| 項目 | 設計 |
|---|---|
| 日誌（與封鎖機制一起做） | 改用 `log/slog` 的 JSON handler 輸出到 stdout。`LOG_LEVEL` 預設 `info`：只記錄事件、封鎖、錯誤、啟動與憑證載入。`debug` 才記錄每筆請求與 listener 丟棄的連線 |
| `UPSTREAM_SERVER_NAME` | ✅ 已完成。設定後 `tls.Config{ServerName: 該值}`，以網域名稱驗證 DSM 憑證，忽略 `UPSTREAM_INSECURE`。兩者都設時在啟動日誌提示 |
| 嚴格 SNI（隱身）🟡 第二層 | 設了 `ALLOWED_HOSTS` 時，`GetCertificate` 檢查 `ClientHelloInfo.ServerName`（不分大小寫），不在清單就回錯誤、**不送出憑證**，握手中斷。用 IP 盲掃的掃描器拿不到憑證，也就拿不到網域。不新增環境變數；沒設 `ALLOWED_HOSTS` 時行為不變；只在 HTTPS 模式生效。HTTP 層的 Host 檢查（404）保留，處理 SNI 正確但 `Host` 不同的請求。同 nginx 的 `ssl_reject_handshake on`。限制：TCP 交握仍會成功（port 看得到）；網域已在 Certificate Transparency 日誌公開，擋不住從那裡拿到網域的掃描器 |
| body 上限 ✅ | `verify()` 開頭 `r.Body = http.MaxBytesReader(w, r.Body, 4<<10)`；超過時回 `413`。Turnstile token 最長約 2 KB，4 KB 足夠。理由：`ParseForm` 預設讀到 10 MB，在 `GOMEMLIMIT=48MiB` 下幾個並發 POST 就有記憶體壓力 |
| 上游逾時 🟡 第二層 | 上游 `http.Transport` 加 `DialContext`（`net.Dialer{Timeout: 5s}`）與 `TLSHandshakeTimeout: 10s`，後端卡住時不耗光 goroutine。**不設** `ResponseHeaderTimeout`，避免切斷 DSM 長輪詢與大檔下載 |
| header 上限 ✅ | `http.Server.MaxHeaderBytes` 由預設 1 MB 改為 64 KB |
| 驗證頁安全標頭 🟡 第二層 | 只加在 `/__gate` 回應（不加在轉發的回應）：`Content-Security-Policy: frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。**不做完整 CSP**：頁面有內嵌 script，要 hash／nonce，還要列 Turnstile 與字型來源，改頁面時容易漏改而壞掉；頁面沒有敏感操作、樣板已跳脫，效益低（見 §8） |
| Go 版本 | `go.mod` 為 `go 1.27`，與 Dockerfile 的 `golang:1.27-alpine` 一致。Go 只維護最新兩個大版本，舊版不再收到安全修補（2026-10-30 CI 的 `govulncheck` 在 go1.25.14 抓到 net/http、crypto/tls、crypto/x509 等 10 個只修在 1.26.9 以後的漏洞）。新大版本推出時（約每年 2 月、8 月），`go.mod` 與 Dockerfile 一起升 |
| 設定 ✅ | `loadConfig() error` 在 `main()` 開頭讀環境變數並設定既有的 package 變數（`needEnv`、`parseUpstream` 回傳 error），錯誤訊息與預設值不變；`go test` 不需任何環境變數。採最小改法，沒有引入 `type config struct`／`*gate`；封鎖機制實作時若 handler 需要持有狀態再評估 |
| CI ✅（釘選 SHA 為 🟡 第二層） | `build.yml` 加 `schedule: - cron: "0 3 * * 1"`（每週一重建，帶入 Go、alpine、CA 的修補版：`golang:1.27-alpine` tag 會跟上 1.27.x，但映像要重建才吃得到）；test job 加 `go test -race ./...` 與 `govulncheck ./...`（`govulncheck@v1.1.4`，固定版本）。排程觸發時 `image` job 照常推送 `latest`，`routeros-tar` 也會每週產出 artifact。第二層：所有 action 釘選 commit SHA（`uses: actions/checkout@<sha> # v7`），由 dependabot 更新 |
| 測試 ✅ | `gate_test.go` 涵蓋現有函式：`safeNext`（含 `/./\evil.com`、TAB／LF／CR，並檢查 `http.Redirect` 寫出的 Location）、`hasDotDot`、`allowedHost`、cookie 簽章（有效、過期、竄改、格式錯誤、換金鑰）、`verify` 的 body 上限與無 token 時的導向、`serveFont`。主路由的 bypass 判斷是 `main()` 內的 closure，未直接測試（組成函式皆已覆蓋）。封鎖機制的測試見 §6 第 7 項 |

### 3.7 檔案配置

維持「單一 `main.go`」：封鎖相關約 100 行，`main.go` 預估 450～500 行，仍好讀。

| 檔案 | 變更 |
|---|---|
| `main.go` | 加入 `blocker`、`blockListener`、`cookieState`、slog、嚴格 SNI、上游逾時、驗證頁安全標頭（✅ 已有：`loadConfig`、Host 檢查、上游憑證驗證、body 與 header 上限） |
| `gate_test.go` | ✅ 已新增（現有函式）；封鎖機制完成後補上事件、封鎖時長、`blockListener`。測試檔不進映像（Dockerfile 只複製 `go.mod`、`main.go`、`fonts/`） |
| `go.mod` | ✅ `go 1.27` |
| `.github/workflows/build.yml` | ✅ 每週排程、`go test -race`、`govulncheck`；第二層：action 釘選 SHA |
| `deploy/mikrotik-gate.rsc` | 見 §3.8 |
| `deploy/docker-compose.yml` | ✅ 已完成 |
| `README.md` | 特色加「自動封鎖」；環境變數表；新增「封鎖機制」小節；建置段落加測試指令 |
| `docs/blocking.md` | **新增**。事件、封鎖時長、防誤封、日誌格式、如何查詢與解除（重啟容器） |
| `docs/deploy-mikrotik.md` | envs 說明；U2～U4 的建議設定（`domain` 變數範例、U5 NTP 已完成） |
| `docs/security.md` | 「擋什麼、不擋什麼」加入封鎖機制；FAQ「`GATE_KEY` 外洩」補充：換金鑰只會讓所有人重新驗證，不會被封鎖 |
| `docs/cert-sync-dsm.md` | §5 排程補上「僅在異常終止時寄信」（U6）與萬用字元憑證說明（U1） |
| `CHANGES-blocking.md` | **新增**。本次異動說明 |

### 3.8 RouterOS（`.rsc`）

✅ 已完成：`domain` 變數、`UPSTREAM_SERVER_NAME`、`ALLOWED_HOSTS`，並刪除 `UPSTREAM_INSECURE`（RouterOS 7.24+ 語法 `list=`）。`GOMEMLIMIT` 改由映像預設，`.rsc` 不再設定。

已部署的路由器不重新匯入，改為 `stop` → 調整 envs → `repull` → `start`（指令見 `docs/deploy-mikrotik.md`「更新映像」）。

### 3.9 新的環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `ALLOWED_HOSTS` | 不檢查 | ✅ Host 檢查已完成（不符回 404）。允許的網域，逗號分隔，不分大小寫，去掉 port。**強烈建議設定**，否則 `bad_host` 不會生效 |
| `UPSTREAM_SERVER_NAME` | 無 | ✅ 已完成。驗證上游憑證時使用的網域名稱。設定後忽略 `UPSTREAM_INSECURE` |
| `LOG_LEVEL` | `info` | `debug` 時逐筆記錄請求 |
| `GOMEMLIMIT` | `48MiB` | ✅ Dockerfile 以 `ENV` 設為預設，可用環境變數覆寫。Go runtime 內建 |

### 3.10 日誌格式

```json
{"time":"...","level":"INFO","msg":"event","event":"verify_fail","ip":"203.0.113.50","host":"dsm512.example.me","ua":"...","errors":["invalid-input-response"]}
{"time":"...","level":"WARN","msg":"blocked","ip":"203.0.113.50","event":"verify_fail","strike":2,"duration":"24h0m0s"}
{"time":"...","level":"ERROR","msg":"siteverify","err":"context deadline exceeded"}
```

日誌欄位不放 cookie 值與 token。

## 4. 規模與可靠性

| 情境 | 估算 | 結論 |
|---|---|---|
| 正常流量 | 家用，同時在線個位數 | 無瓶頸 |
| 被掃描 | 路由器限制每 IP 20 條同時連線、每分鐘 30 條新連線 | 封鎖後每條連線只花 accept + close；不寫日誌 |
| 分散式掃描 | 大量不同 IP 各打一次 | 每個 IP 只產生一筆事件日誌，表上限 50,000 筆防止記憶體失控 |
| 容器重啟 | 封鎖表清空 | 可接受：bot 會再觸發一次就再封鎖 |
| siteverify 連不上 | 驗證全部失敗 | 不算事件，不會誤封；已有 cookie 的使用者不受影響 |
| 誤封真人 | 同一 NAT 後方有 bot、或人手動亂打 cookie | 重啟容器即可解除；文件說明 |

## 5. 取捨

| 決策 | 選擇 | 放棄了什麼 | 理由 |
|---|---|---|---|
| 封鎖位置 | 閘門 listener | 封包在路由器丟棄的效益 | 少了腳本與防火牆這些會壞的環節 |
| 事件種類 | 只有 3 種「真人不會觸發」的 | 對慢速掃描器（不帶 cookie、只打 API）的偵測 | 寧可漏封也不誤封；這類請求本來就只拿到 401 |
| 計分 | 不計分，事件直接封鎖 | 調整敏感度的彈性 | 三種事件都很明確，不需要加權 |
| 封鎖狀態 | 只存在記憶體 | 重啟後保留 | 不需要磁碟寫入，也不會累積髒資料 |
| 參數 | 寫死常數 | 環境變數調整 | 目前沒有調整的需求，需要時再加 |
| 檔案 | 單一 `main.go` | 模組化 | 保持「單檔反向代理」的定位 |
| 分享情報 | 不做（不提供封鎖清單、不回報 AbuseIPDB） | 聯防 | 單一閘門的視野有限，誤報公開回報的風險大於效益 |

## 6. 實作計畫

| 順序 | 項目 | 驗收條件 |
|:-:|---|---|
| 1 | ✅ `go.mod`、`loadConfig` | `go test ./...` 不設任何環境變數也能跑 |
| 2 | slog | 預設等級下，連續 100 個無 cookie 的 API 請求不產生任何日誌 |
| 3 | `cookieState` | 更換 `GATE_KEY` 後帶舊 cookie：瀏覽器被導向驗證頁且 cookie 被清除，IP 未被封鎖 |
| 4 | `blocker`、`ALLOWED_HOSTS`、三種事件 | 錯誤 Host 1 次即封鎖；`verify_fail` 第 1 次不封、10 分鐘內第 2 次封鎖；私有 IP 永不封鎖；favicon 與無 cookie 的 API 請求不產生事件 |
| 5 | `blockListener`、累犯加重 | 被封鎖的 IP 連線 TLS 握手失敗（`curl` 顯示連線被重設）；7 天內第 2 次封鎖 24 小時、第 3 次 7 天；`TRUST_CF_HEADER=1` 時不包 listener，改回 403 |
| 6 | 嚴格 SNI、上游逾時、驗證頁三個安全標頭（✅ 已完成：上游憑證驗證、body 上限、header 上限） | `openssl s_client -connect <IP>:8443`（不帶 `-servername`）與錯誤的 `-servername` 都拿不到憑證，正確網域正常；上游 IP 連不上（不回 SYN-ACK）時約 5 秒回 502；`/__gate` 帶 `frame-ancestors`、`nosniff`、`Referrer-Policy`，轉發的回應不帶 |
| 7 | `gate_test.go`（✅ 現有函式已涵蓋） | 補上 `cookieState` 五種狀態、事件與封鎖時長（以可注入的 `now` 測試）、私有 IP、`blockListener` |
| 8 | CI（✅ 排程、`go test -race`、`govulncheck`） | 所有 `uses:` 都是 commit SHA，dependabot 能開出更新 PR |
| 9 | `.rsc`、compose、文件 | 文件中的環境變數與程式一致；`grep -r UPSTREAM_INSECURE` 只剩說明「可選」的地方 |
| 10 | `CHANGES-blocking.md` | 包含摘要、行為變更、環境變數、檔案異動、升級注意事項、驗證狀態 |

**選做（低優先）：** cookie 剩不到一半效期時自動續簽；路由器加 Spamhaus DROP 清單；誘餌登入頁（見 [DESIGN-decoy.md](DESIGN-decoy.md)）。

### 開發與驗證指令

```bash
gofmt -l . && go vet ./...
go test -race ./...
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o gate-arm64 .
```

本機端到端：用 `python -m http.server` 當假上游，閘門 `LISTEN=:8095` 啟動，以 `curl -H "Host: ..."` 模擬。要模擬公網 IP，暫時開 `TRUST_CF_HEADER=1` 搭配 `CF-Connecting-IP`（此時走 handler 層封鎖；listener 層要另外以單元測試覆蓋）。siteverify 以 `httptest.Server` mock，連不到真正的 Cloudflare 時也能測。

## 7. 待使用者決定或設定

### 7.1 決策

| # | 問題 | 預設處理 |
|---|---|---|
| D1 | 封鎖在閘門內（A）還是通知路由器（B）？ | 本文件採用 **A**。若改 B，見 §3.1 的備註 |
| D2 | DSM 網域 | ✅ 已確定：`ninja218j.myds.me`。`.rsc` 與 compose 是給他人用的範本，維持 `nas.example.com`／`你的網域` 佔位 |
| — | 所有 `OWNER` 佔位符要換成哪個 GitHub 帳號？ | ✅ 已確定：`sinnoken`（映像 `ghcr.io/sinnoken/turnstile-gate`）。`LICENSE` 著作權人另行決定 |

### 7.2 使用者自行設定（會寫進文件）

| # | 項目 |
|---|---|
| U1 | 確認 DSM 憑證是 `*.dsm512.xxx` 萬用字元憑證。是的話走 DNS-01，不需要對外開 80 |
| U2 | RB5009 開 WireGuard：閘門故障時能連回家修理；手機 App（DS File、Photos）也走這條 |
| U3 | 外部監控（UptimeRobot 等），檢查 `https://<網域>/__gate` 是否可連、憑證何時到期 |
| U4 | Split DNS：`/ip/dns/static add name=<網域> address=<NAS IP>` |
| U5 | 確認 `/system/ntp/client` 已啟用（RB5009 沒有時鐘電池，時間錯會讓 cookie 與憑證驗證失效） |
| U6 | DSM 排程：以 root 每天執行 `dsm-push-cert.sh`，勾選「僅在異常終止時寄信」 |
| U7 | DSM 把 `172.17.0.2` 加進受信任的 Proxy；關閉 QuickConnect 與 UPnP；Synology DDNS 不要開 IPv6 自動更新 |

## 8. 日後要重新檢視的地方

- **封鎖紀錄顯示大量 IP 重複出現**：考慮改成或加上方案 B，讓路由器在更外層丟棄。
- **閘門升級頻繁導致封鎖表常被清空**：考慮把封鎖表定期寫到掛載的磁碟。
- **IPv6 流量明顯增加**：封鎖鍵改成 IPv6 `/64` 前綴。
- **慢速掃描器成為困擾**：再評估加入低權重事件，但必須先有實際日誌數據證明不會誤封。
- **開放 port 80 或加入 HTTP→HTTPS 轉址**：加上 HSTS（`Strict-Transport-Security: max-age=31536000`，HTTPS 模式；轉發時在 `ModifyResponse` 刪掉 DSM 自己的 HSTS 避免重複）。目前 port 80 未轉發、DSM 登入後本身就送 HSTS，降級攻擊空間很小。
- **驗證頁加入使用者輸入或第三方內容**：再評估完整 CSP（內嵌 script 改用 hash／nonce，列出 Turnstile 與字型來源）。
- **改用不在 public suffix list 上的自有網域**：評估 HTTPS 模式改用 `__Host-gate` cookie（瀏覽器強制 `Secure`、`Path=/`、不可帶 `Domain`；改名會讓所有人重新驗證一次，`stripGateCookie` 兩個名稱都要移除）。目前 cookie 有 HMAC 簽章，注入的 cookie 本來就無效。
- **刪除上游 `Server` 標頭**：只有通過驗證的人看得到上游回應，目前效益接近零；有需要時在 `ModifyResponse` 刪除。
- **`verify_fail` 與共用 IP**：同一 CGNAT IP 後兩人各失敗一次就會一起被封；實作封鎖機制時評估提高門檻，或只讓 `bad_host`、`bad_cookie`、`decoy_hit` 觸發封鎖。
