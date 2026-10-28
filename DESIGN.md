# 設計文件：turnstile-gate 封鎖機制與強化

接下來開發的依據。讀完就能開工。

---

## 1. 背景與限制

```
網際網路 ─443─→ MikroTik RB5009（RouterOS v7，dst-nat）
                   └→ 容器 turnstile-gate 172.17.0.2:8443（TLS + Turnstile + HMAC cookie + 封鎖）
                         └─HTTPS─→ Synology DSM（內網 NAS:5001）
```

- 家用環境，容器跑在 RB5009（arm64）上，記憶體與儲存都有限。
- DSM 網域使用 Synology DDNS，前綴 `dsm512.`，**完整後綴待確認（D2）**。
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
| F6 | 上游可以用內網 IP 連線，同時用網域名稱驗證 DSM 憑證 |

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
TLS 握手（certLoader 熱更新）
  │
  ▼
handler
  ├─ 加上 HSTS
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
| `bad_host` | 設定了 `ALLOWED_HOSTS`，且 `Host`（去掉 port、不分大小寫）不在清單內 | 立即封鎖，回 `404` | 真人只會用網域連線；直接打 IP 的是掃描器 |
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
| 日誌 | 改用 `log/slog` 的 JSON handler 輸出到 stdout。`LOG_LEVEL` 預設 `info`：只記錄事件、封鎖、錯誤、啟動與憑證載入。`debug` 才記錄每筆請求與 listener 丟棄的連線 |
| `UPSTREAM_SERVER_NAME` | 設定後 `tls.Config{ServerName: 該值}`，以網域名稱驗證 DSM 憑證，忽略 `UPSTREAM_INSECURE`。兩者都設時在啟動日誌提示 |
| body 上限 | `verify()` 開頭 `r.Body = http.MaxBytesReader(w, r.Body, 4<<10)`；`ParseForm` 失敗回 `413`。Turnstile token 最長約 2 KB，4 KB 足夠 |
| HSTS | 只在 HTTPS 模式加上 `Strict-Transport-Security: max-age=31536000`。轉發的回應在 `ModifyResponse` 先刪掉 DSM 自己的 HSTS，避免重複標頭 |
| Go 版本 | `go.mod` 改成 `go 1.24`，與 Dockerfile 的 `golang:1.24-alpine` 一致 |
| 設定 | 新增 `type config struct` 與 `loadConfig() (*config, error)`，在 `main()` 呼叫。package `var` 不再讀環境變數。handler 與 `blocker` 以 `*gate` 結構持有設定，測試直接建構 |
| CI | `build.yml` 加 `schedule: - cron: "0 3 * * 1"`（每週一重建，拿到新的 base image 與 CA）；test job 加 `go test -race ./...` 與 `govulncheck ./...`。排程觸發時 `image` job 照常推送 `latest` |

### 3.7 檔案配置

維持「單一 `main.go`」：封鎖相關約 100 行，`main.go` 預估 450～500 行，仍好讀。

| 檔案 | 變更 |
|---|---|
| `main.go` | 加入 `config`／`loadConfig`、`blocker`、`blockListener`、`cookieState`、Host 檢查、slog、上游憑證驗證、body 上限、HSTS |
| `gate_test.go` | **新增**。測試檔不需要進映像，`Dockerfile` 與 `.dockerignore` **不用改** |
| `go.mod` | `go 1.24` |
| `.github/workflows/build.yml` | 每週排程、`go test -race`、`govulncheck` |
| `deploy/mikrotik-gate.rsc` | 見 §3.8 |
| `deploy/docker-compose.yml` | 新增 `ALLOWED_HOSTS`、`UPSTREAM_SERVER_NAME`、`GOMEMLIMIT`；`UPSTREAM_INSECURE` 改為註解 |
| `README.md` | 特色加「自動封鎖」；環境變數表；新增「封鎖機制」小節；建置段落加測試指令 |
| `docs/blocking.md` | **新增**。事件、封鎖時長、防誤封、日誌格式、如何查詢與解除（重啟容器） |
| `docs/deploy-mikrotik.md` | 變數範例加 `domain`；envs 說明；U2～U5 的建議設定 |
| `docs/security.md` | 「擋什麼、不擋什麼」加入封鎖機制；FAQ「`GATE_KEY` 外洩」補充：換金鑰只會讓所有人重新驗證，不會被封鎖 |
| `docs/cert-sync-dsm.md` | §5 排程補上「僅在異常終止時寄信」（U6）與萬用字元憑證說明（U1） |
| `CHANGES-blocking.md` | **新增**。本次異動說明 |

### 3.8 RouterOS（`.rsc`）

只改變數與第 6 段：

```
:local domain  "dsm512.EXAMPLE.me"   ;# DSM 的網域（D2）
...
/container/envs/add name=gate key=ALLOWED_HOSTS        value=$domain
/container/envs/add name=gate key=UPSTREAM_SERVER_NAME value=$domain
/container/envs/add name=gate key=GOMEMLIMIT           value="48MiB"
```

刪除 `UPSTREAM_INSECURE` 那行（改由 `UPSTREAM_SERVER_NAME` 驗證憑證）。

### 3.9 新的環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `ALLOWED_HOSTS` | 不檢查 | 允許的網域，逗號分隔，不分大小寫，去掉 port。**強烈建議設定**，否則 `bad_host` 不會生效 |
| `UPSTREAM_SERVER_NAME` | 無 | 驗證上游憑證時使用的網域名稱。設定後忽略 `UPSTREAM_INSECURE` |
| `LOG_LEVEL` | `info` | `debug` 時逐筆記錄請求 |
| `GOMEMLIMIT` | 無 | Go runtime 內建，建議 `48MiB` |

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
| 1 | `go.mod`、`config`／`loadConfig` | `go test ./...` 不設任何環境變數也能跑 |
| 2 | slog | 預設等級下，連續 100 個無 cookie 的 API 請求不產生任何日誌 |
| 3 | `cookieState` | 更換 `GATE_KEY` 後帶舊 cookie：瀏覽器被導向驗證頁且 cookie 被清除，IP 未被封鎖 |
| 4 | `blocker`、`ALLOWED_HOSTS`、三種事件 | 錯誤 Host 1 次即封鎖；`verify_fail` 第 1 次不封、10 分鐘內第 2 次封鎖；私有 IP 永不封鎖；favicon 與無 cookie 的 API 請求不產生事件 |
| 5 | `blockListener`、累犯加重 | 被封鎖的 IP 連線 TLS 握手失敗（`curl` 顯示連線被重設）；7 天內第 2 次封鎖 24 小時、第 3 次 7 天；`TRUST_CF_HEADER=1` 時不包 listener，改回 403 |
| 6 | 上游憑證驗證、body 上限、HSTS | 設 `UPSTREAM_SERVER_NAME` 後可驗證上游憑證；5 KB body 回 413；HTTPS 回應只有一個 HSTS 標頭 |
| 7 | `gate_test.go` | 涵蓋 `safeNext`、`cookieState` 五種狀態、事件與封鎖時長（以可注入的 `now` 測試）、私有 IP、Host 檢查、`blockListener`、body 上限 |
| 8 | CI | YAML 語法正確；`govulncheck` 在本機可跑 |
| 9 | `.rsc`、compose、文件 | 文件中的環境變數與程式一致；`grep -r UPSTREAM_INSECURE` 只剩說明「可選」的地方 |
| 10 | `CHANGES-blocking.md` | 包含摘要、行為變更、環境變數、檔案異動、升級注意事項、驗證狀態 |

**選做（低優先）：** cookie 剩不到一半效期時自動續簽；路由器加 Spamhaus DROP 清單。

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
| D2 | DSM 網域完整後綴（`dsm512.???`） | `.rsc` 與 compose 先用 `dsm512.EXAMPLE.me` 佔位 |
| — | 所有 `OWNER` 佔位符要換成哪個 GitHub 帳號？ | 保留 `OWNER` |

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
