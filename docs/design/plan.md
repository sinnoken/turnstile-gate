# 開發計畫：turnstile-gate 封鎖機制

讀完就能開工。誘餌登入頁（選做）見 [decoy.md](decoy.md)。

## 0. 範圍

| 要做 | 內容 |
|---|---|
| 封鎖機制 | 閘門判斷「確定不是真人」的 IP 並立即封鎖（A），再把封鎖清單交給路由器在最外層丟棄（B）。§3、§4 |
| 第二層強化 | 嚴格 SNI、上游逾時、驗證頁安全標頭、action 釘選 SHA。便宜就做，與封鎖機制無關。§5 |
| 使用者設定 | 路由器、DSM、外部監控的設定。§8 |

起點：閘門已能驗證、轉發，`ALLOWED_HOSTS` 不符回 `404`（改為 `421`，§4.1），`go test` 不需環境變數。

---

## 1. 背景與限制

```
                      ┌──────────── 每分鐘拉取封鎖清單（B）────────────┐
                      ▼                                                │
網際網路 ─443─→ MikroTik RB5009（raw 丟棄、dst-nat）                    │
                      └→ 容器 turnstile-gate 172.17.0.2:8443 ─────────┤ :9090 封鎖清單 JSON
                           （TLS、Turnstile、HMAC cookie、封鎖判斷 A）
                           └─HTTPS─→ Synology DSM（內網 NAS:5001）
```

- 家用環境，容器跑在 RB5009（arm64）上，記憶體與儲存有限（`GOMEMLIMIT=48MiB`）。
- DSM 網域 `ninja218j.myds.me`（Synology DDNS）；憑證來自 DSM 的 Let's Encrypt，由 DSM 排程推送到路由器。
- **閘門直接對外**，不經過 Cloudflare 代理或 Tunnel；只有 Turnstile 用到 Cloudflare。

### 1.1 原則

- **輕量、精簡、有效**；不為理論風險增加複雜度；依實際數據調整。
- Turnstile 只擋 bot，不負責身分驗證；身分驗證交給 DSM 的密碼與 2FA。
- **寧可漏封，不要誤封**：只封鎖「確定不是真人」的 IP，封鎖 1 小時起跳。
- 封鎖表只放**主動做出某件事**的 IP（偽造 cookie、偽造或重複送 token）；盲掃與送錯網域的雜訊交給 TLS 層（嚴格 SNI）、`Host` 檢查與路由器限速，不佔表格。
- 不用 CrowdSec、Anubis、ALTCHA、AbuseIPDB。
- 文件一律用 **繁體中文**（台灣用語）。

### 1.2 不要做的事

- 不要加入「真人也會觸發」的事件（例如沒有 cookie 的請求）。
- 不要讓容器拿到 RouterOS 的 API 帳密（RouterOS 無法只開放 address-list）。
- 不要把 DSM 的 80、5000、5001 直接轉發到外部，會繞過閘門。
- 不要在直接對外時預設開啟 `TRUST_CF_HEADER`，會讓攻擊者偽造來源 IP。
- 不要引入第三方 Go 套件；維持標準函式庫、單一執行檔（CI 工具如 `govulncheck` 不算相依套件）。
- 不要為 IPv6 加任何機制。

## 2. 需求

### 2.1 功能需求

| # | 需求 |
|---|---|
| F1 | 只有兩種事件：`bad_cookie`、`verify_fail`（依錯誤碼分強、弱）。SNI 或 `Host` 不符、沒有 cookie 的 API、favicon、DSM 背景請求一律不算事件 |
| F2 | 被封鎖的 IP 在 listener 層直接關閉連線，不做 TLS 握手 |
| F3 | 累犯加重：7 天內第 1 次封 1 小時、第 2 次 24 小時、第 3 次以上 7 天 |
| F4 | 換 `GATE_KEY` 後，舊 cookie 只讓使用者重新驗證一次，不會被封鎖 |
| F5 | 私有、loopback、link-local IP 永不封鎖 |
| F6 | 以 JSON 提供目前封鎖中的 IP 與剩餘時間，讓路由器拉取後在最外層丟棄 |

### 2.2 非功能需求

| 項目 | 目標 |
|---|---|
| 記憶體 | 封鎖表上限 50,000 筆，約 10～12 MB（§4.3），在 `GOMEMLIMIT=48MiB` 內 |
| 日誌量 | 被掃描時不洗掉 RouterOS `/log`：預設只記錄事件、封鎖、錯誤，以及每小時一行表格大小 |
| 程式量 | 封鎖相關 Go 約 130 行（含封鎖清單 JSON 約 30 行），維持單一 `main.go`；RouterOS 腳本約 15 行 |
| 可測試性 | `go test` 不需要任何環境變數 |
| 狀態 | 閘門封鎖表只存在記憶體，重啟即清空；路由器 address-list 照時效保留 |

## 3. 架構

### 3.1 兩層封鎖

| | **A. 閘門封鎖** | **B. 路由器丟棄** |
|---|---|---|
| 角色 | **判斷者**：事件、累犯、時長都在這裡決定 | **執行者**：只照清單丟封包，不做判斷 |
| 做法 | 封鎖表在記憶體；`blockListener` 在 `Accept()` 時直接 `Close()` | 路由器每分鐘拉閘門的 JSON 清單，寫進有時效的 address-list `gate-block`，raw prerouting 丟棄 |
| 生效 | 事件當下 | 最多延遲約 1 分鐘 |
| 效果 | 封包仍到容器，只花一次 accept + close | 在最外層丟棄，不進 conntrack、不經 NAT、不到容器 |
| 閘門重啟 | 封鎖表清空 | address-list 項目照時效保留 |

- A 即時、可靠，也是唯一做判斷的地方；B 把已判定的 IP 推到最外層，省下路由器 conntrack 與容器的連線處理，並撐過閘門重啟或 `repull`。
- B 壞了（腳本錯、閘門沒回應）A 照常運作；address-list 項目有時效，拉不到新清單只會自然到期，不會留下永久封鎖。
- 由路由器來拉：容器不需要、也不能拿到 RouterOS 帳密（§1.2）。

### 3.2 請求流程

```
封包（WAN）
  ▼
路由器 raw prerouting：來源在 gate-block？──是──→ 丟棄（B）
  ▼ 否
TCP 連線（dst-nat 到容器）
  ▼
blockListener.Accept()：來源封鎖中？──是──→ Close()（debug 記錄）
  ▼ 否
TLS 握手 ── 嚴格 SNI：SNI 不在 ALLOWED_HOSTS ──→ 中斷握手（debug 記錄，不算事件）
  ▼
handler
  ├─ 來源封鎖中？（keep-alive 連線、TRUST_CF_HEADER 時）──→ 403 + Connection: close
  ├─ Host 不在 ALLOWED_HOSTS ──→ 421（debug 記錄，不算事件）
  ├─ GET /__gate ──→ 驗證頁
  ├─ POST /__gate/verify（body ≤ 8 KB）──→ siteverify
  │     ├─ body 沒讀完或格式錯誤 ──→ 400（不呼叫 siteverify，不算事件）
  │     ├─ 通過 ──→ 發 cookie → 導回 next
  │     ├─ 強訊號（token 為空、偽造、他站 token）──→ 事件 verify_fail → 立即封鎖
  │     ├─ 弱訊號（timeout-or-duplicate）──→ 事件 verify_fail → 10 分鐘內第 2 次才封鎖 → 驗證頁 ?err=1
  │     └─ 連線錯誤、secret 錯誤、internal-error ──→ 只記錄錯誤，不算事件
  └─ 其他路徑：cookieState()
        ├─ valid ─────────────→ 轉發上游
        ├─ BYPASS_PREFIXES ───→ 轉發上游
        ├─ malformed（所有 __gate 都格式錯誤）→ 事件 bad_cookie → 封鎖 → 403
        ├─ badsig / expired ──→ 清除 cookie（不算事件）┐
        └─ none ──────────────────────────────────────┴→ 瀏覽器：導向驗證頁；其他：401
```

## 4. 詳細設計

### 4.1 事件

封鎖事件都需要對方**主動做出某件事**才會觸發：

| 事件 | 觸發條件 | 處理 | 為什麼真人不會觸發 |
|---|---|---|---|
| `bad_cookie` | 請求帶的**所有** `__gate` cookie 都格式錯誤：沒有 `.`、到期時間不是數字、簽章不是 64 字元 hex | 立即封鎖，回 `403` | 閘門發的 cookie 格式永遠正確（格式變更規則見 §4.2），換金鑰也不變 |
| `verify_fail`（強） | token 為空；siteverify 錯誤碼 `invalid-input-response` 或 `bad-request`；hostname 不符 | 立即封鎖 | 驗證頁只在 Turnstile 回呼後才自動送出表單，真人送出的一定有 token；空 token 是程式直接 POST，後三者是偽造或拿別的網站產生的 token |
| `verify_fail`（弱） | siteverify 錯誤碼 `timeout-or-duplicate` | 10 分鐘內第 1 次只記錄，第 2 次封鎖 | token 超過 5 分鐘或重複送出（按上一頁）偶爾會發生，不會連續發生 |

**不是事件的**（只記錄，不入封鎖表）：

| 情況 | 處理 | 理由 |
|---|---|---|
| SNI 不符（嚴格 SNI，§5） | 中斷握手，debug 記錄 | 盲掃的掃描器一週可能有數千到上萬個來源，握手階段就拿不到任何東西；封鎖只省一次 ClientHello，卻要佔 7 天的表格、讓 B 的清單變大、讓 CGNAT 後的真人更容易被連帶封鎖 |
| `Host` 不在 `ALLOWED_HOSTS` | 回 `421 Misdirected Request`，debug 記錄 | 沒做嚴格 SNI 時，這裡抓到的是同一群盲掃（`Host` 是 IP）；做了嚴格 SNI 後，SNI 正確但 `Host` 不同多半是 **HTTP/2 連線共用**（瀏覽器把同一 IP、同一張憑證涵蓋的不同網域放在同一條連線），`421` 是規範的回應，瀏覽器會另開連線重試 |
| siteverify 錯誤碼 `missing-input-secret`、`invalid-input-secret`、`internal-error`，或連線錯誤 | error 記錄 | 閘門設定錯誤或 Cloudflare 的問題，不是使用者的錯 |
| verify 的 body 沒讀完或無法解析 | 回 `400`，不呼叫 siteverify | 驗證頁通過後會自動送出，使用者此時重新整理、按上一頁或行動網路中斷，body 就會中途斷掉；不能當成空 token |
| 沒有 cookie、favicon、DSM 背景請求 | 不記錄 | 真人也會產生 |

- `Host` 比對：去掉 port 與結尾的 `.`（`ninja218j.myds.me.` 是合法寫法），不分大小寫。
- `verify_fail` 的強弱分級讓真人唯一會碰到的錯誤碼保留容錯；CGNAT 後被連帶封鎖，只會發生在兩個人 10 分鐘內各自碰到 `timeout-or-duplicate`。上線後依錯誤碼分布檢討（§10）。
- Turnstile 元件端的錯誤（例如 `110200` 網域未授權）不會產生 token、也不會送出表單，不會變成事件。

### 4.2 cookie 狀態

以 `cookieState()` 替換 `validCookie()`：

| 狀態 | 條件 | 處理 |
|---|---|---|
| `none` | 沒有 cookie | 導向驗證頁或 401 |
| `valid` | 格式、簽章正確，未過期 | 轉發 |
| `expired` | 格式、簽章正確，已過期 | 清除 cookie，導向驗證頁或 401 |
| `badsig` | 格式正確，簽章不符（通常是換了 `GATE_KEY`） | 清除 cookie（`Max-Age=-1`），導向驗證頁或 401，**不算事件** |
| `malformed` | 格式錯誤 | `bad_cookie` 事件 |

- **多個同名 cookie**：讀取請求裡所有 `__gate`，任一個是 `valid` 就放行；有 `valid` 以外的狀態時取最寬鬆的處理（`expired`、`badsig` 優先於 `malformed`）；**全部都是 `malformed` 才算 `bad_cookie`**。
- **格式變更規則**：日後若改 cookie 格式（加版本號、換分隔符號等），舊格式必須辨識為 `badsig`（清除、不算事件），至少保留一個 `SESSION_HOURS` 的過渡期，否則所有使用者的舊 cookie 都會被當成 `malformed` 而集體封鎖。
- cookie 不加金鑰版本號：`badsig` 不算事件，版本號沒有額外好處。

### 4.3 封鎖表

```go
type offender struct {
	until    time.Time // 封鎖到期；零值 = 未封鎖
	strikes  int       // 7 天內被封鎖的次數
	lastHit  time.Time // 最後一次被封鎖（判斷 7 天視窗）
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
| `hit(ip, event)` | 私有 IP 只記錄不封；弱 `verify_fail` 先看 `failedAt` 是否在 10 分鐘內，不是就只更新 `failedAt`；`bad_cookie`、強 `verify_fail` 與第 2 次弱 `verify_fail` 封鎖：`lastHit` 超過 7 天則 `strikes` 歸零，`strikes++`，依次數決定時長，記錄 `blocked` 日誌 |
| `sweep()` | 每 10 分鐘：刪除 `until`、`lastHit + 7d`、`failedAt + 10m` 都已過期的項目；每小時記一行 info：總筆數、封鎖中筆數 |
| `list() []entry` | 給 §4.5：目前封鎖中的 IPv4 與剩餘秒數 |

| 7 天內第幾次 | 時長 |
|:-:|---|
| 1 | 1 小時 |
| 2 | 24 小時 |
| ≥ 3 | 7 天 |

**上限與表滿**：

- 上限 50,000 筆。每筆約 200～250 bytes（字串 key、三個 `time.Time`、指標與 map 開銷），滿載約 10～12 MB。SNI 與 `Host` 不符都不入表，正常情況遠低於上限。
- 表滿時要新增 IP：先刪一筆「**沒在封鎖、只剩累犯或 `verify_fail` 紀錄**」的項目（`lastHit` 最舊的優先）再新增；全部都在封鎖中才放棄新增，並記一行 warn；到最早一筆解封前都直接放棄，不再掃描（掃 50,000 筆要握著全域鎖數毫秒）、不再記錄。確保最新的攻擊者仍會被封。
- 依每小時的表格大小日誌調整：長期接近上限時，再把結構壓小（key 用 `uint32` 存 IPv4、時間用 `uint32` 秒，每筆約 40～50 bytes）。

**其他**：

- 私有 IP：`netip.Addr` 的 `IsPrivate() || IsLoopback() || IsLinkLocalUnicast()`；事件照樣記錄，只是不封。
- 門檻、時長、上限寫死在常數，不開環境變數。
- 設定沿用 `loadConfig` 的 package 變數；`blocker` 若需要由 handler 持有再改成結構。

### 4.4 listener 層封鎖

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

- 啟動改為 `net.Listen` → 包 `blockListener` → `srv.ServeTLS(ln, "", "")` 或 `srv.Serve(ln)`。
- **`TRUST_CF_HEADER=1` 時不包 listener**：`RemoteAddr` 是 Cloudflare 節點，封它等於封所有人；改由 handler 依 `clientIP()` 回 `403`。
- handler 內也檢查一次，處理觸發封鎖的那條 keep-alive 連線：回 `403` 加 `Connection: close`。

### 4.5 封鎖清單 JSON 與路由器拉取

**閘門端**：另開只在內部可達的 listener，`BLOCKLIST_LISTEN`（例：`172.17.0.2:9090`），**沒設就不啟用**。WAN 只轉 443→8443，9090 從網際網路連不到。

```
GET /blocklist.json      Cache-Control: no-store；只接受 GET
```

```json
{"generated":"2026-10-31T09:00:00Z","items":[
  {"ip":"203.0.113.50","ttl":3540,"event":"bad_cookie","strike":1},
  {"ip":"198.51.100.7","ttl":86100,"event":"verify_fail","strike":2}
]}
```

| 欄位 | 說明 |
|---|---|
| `items` | **只列目前封鎖中的 IPv4**；累犯紀錄與 IPv6 不輸出 |
| `ttl` | 剩餘秒數（整數），路由器直接當 address-list 的 `timeout` |
| `event`、`strike` | 給人看，寫進 address-list 的 comment；路由器不據此判斷 |

- 清單只含真的在嘗試的 IP，預期很小。RouterOS `/tool/fetch output=user` 讀回的內容有上限（實作前對照手冊確認），超過時只輸出 `ttl` 最長的前 N 筆並記一行 warn。
- 存取：9090 只在容器網段；同區網其他主機理論上連得到，內容只是攻擊者 IP，敏感度低。需要時在 `.rsc` forward 規則限定只有 `172.17.0.1`。

**路由器端**（加進 `.rsc`；語法為草稿，實作時對照 RouterOS 7.24+ 手冊的 `/tool/fetch`、`:deserialize`、`/ip/firewall/address-list` 確認）：

```
/system/script/add name=gate-blocklist source={
  :local r [/tool/fetch url="http://172.17.0.2:9090/blocklist.json" output=user as-value]
  :local j [:deserialize from=json value=($r->"data")]
  :foreach it in=($j->"items") do={
    :local ip ($it->"ip"); :local t [:totime (($it->"ttl") . "s")]
    :local id [/ip/firewall/address-list/find list=gate-block address=$ip]
    :if ([:len $id] = 0) do={
      /ip/firewall/address-list/add list=gate-block address=$ip timeout=$t comment=("gate: " . ($it->"event"))
    } else={ /ip/firewall/address-list/set $id timeout=$t }
  }
}
/system/scheduler/add name=gate-blocklist interval=1m on-event=gate-blocklist comment="gate"
/ip/firewall/raw/add chain=prerouting in-interface-list=WAN src-address-list=gate-block action=drop comment="gate: blocklist"
```

- 拉取失敗：這一輪失敗，既有項目照時效到期，下一分鐘再試。
- 路由器重開機：動態 address-list 項目消失；閘門封鎖表仍在，下一輪補回。
- 已部署的路由器：`stop` → 加 `BLOCKLIST_LISTEN` → `repull` → `start`，再手動加入 script、scheduler、raw 規則。移除步驟要加上這三樣與 address-list `gate-block`。

### 4.6 日誌（slog）

改用標準函式庫 `log/slog` 的 JSON handler 輸出到 stdout：每個欄位有名稱，可分等級，輸出自動跳脫（使用者字串無法偽造出另一行）。`LOG_LEVEL` 預設 `info`。`verify` 的失敗日誌也改成這個格式。

| 等級 | 記錄什麼 |
|---|---|
| `debug` | 每筆請求、listener 丟棄的連線、SNI 不符的握手、`Host` 不符（421） |
| `info` | 事件、啟動、憑證載入、每小時一行表格大小 |
| `warn` | 封鎖、表滿無法新增、封鎖清單被截斷 |
| `error` | siteverify 連線錯誤、上游錯誤 |

```json
{"time":"...","level":"INFO","msg":"event","event":"verify_fail","signal":"weak","ip":"203.0.113.50","host":"nas.example.com","ua":"...","errors":["timeout-or-duplicate"]}
{"time":"...","level":"WARN","msg":"blocked","ip":"203.0.113.50","event":"verify_fail","signal":"strong","strike":2,"duration":"24h0m0s"}
{"time":"...","level":"INFO","msg":"table","entries":184,"blocked":37}
{"time":"...","level":"ERROR","msg":"siteverify","err":"context deadline exceeded"}
```

日誌不放 cookie 值與 token。

### 4.7 環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `LOG_LEVEL` | `info` | 見 §4.6 |
| `BLOCKLIST_LISTEN` | 不啟用 | 封鎖清單 JSON 的監聽位址（例：`172.17.0.2:9090`）；只放內部位址 |
| `ALLOWED_HOSTS` | 既有 | 決定 `Host` 檢查（不符回 `421`）與嚴格 SNI。**強烈建議設定** |

## 5. 第二層強化（便宜就做，與封鎖機制無關）

| 項目 | 設計 |
|---|---|
| 嚴格 SNI（隱身） | 設了 `ALLOWED_HOSTS` 時，`GetCertificate` 檢查 `ClientHelloInfo.ServerName`（不分大小寫），不在清單就回錯誤、**不送出憑證**。用 IP 盲掃的掃描器拿不到憑證與網域。只在 HTTPS 模式；沒設 `ALLOWED_HOSTS` 時行為不變；HTTP 層的 `Host` 檢查（421）保留。擋下的連線只在 debug 記錄，不算事件（§4.1）。同 nginx 的 `ssl_reject_handshake on`。限制：TCP 交握仍成功；網域已在 Certificate Transparency 日誌公開 |
| 上游逾時 | 上游 `http.Transport` 加 `DialContext`（`net.Dialer{Timeout: 5s}`）與 `TLSHandshakeTimeout: 10s`。**不設** `ResponseHeaderTimeout`，避免切斷 DSM 長輪詢與大檔下載 |
| 驗證頁安全標頭 | 只加在 `/__gate`：`Content-Security-Policy: frame-ancestors 'none'`、`X-Content-Type-Options: nosniff`、`Referrer-Policy: no-referrer`。不做完整 CSP（見 §10） |
| action 釘選 SHA | `build.yml` 所有 `uses:` 改成 commit SHA（`actions/checkout@<sha> # v7`），由 dependabot 更新 |

## 6. 規模與可靠性

| 情境 | 估算 | 結論 |
|---|---|---|
| 正常流量 | 家用，同時在線個位數 | 無瓶頸 |
| 被掃描 | 路由器限制每 IP 20 條同時連線、每分鐘 30 條新連線 | 盲掃在 TLS 層被嚴格 SNI 擋下或拿到 421，都不入表；封鎖中的 IP 在路由器丟棄（B）或 accept + close（A）；不寫日誌 |
| 分散式攻擊 | 大量不同 IP 真的觸發事件 | 每個 IP 一筆事件日誌；表滿時淘汰只剩紀錄的項目，最新的攻擊者仍會被封 |
| 容器重啟 | 閘門封鎖表清空 | 路由器端照時效繼續丟棄；累犯次數歸零（可接受） |
| B 拉取失敗 | 路由器拿不到新清單 | A 照常；既有項目自然到期 |
| siteverify 連不上 | 驗證全部失敗 | 不算事件，不會誤封；已有 cookie 的使用者不受影響 |
| 誤封真人 | 同一 NAT 後方有 bot、或手動亂打 cookie | 重啟容器解除閘門端；路由器端刪 address-list `gate-block` 的項目；文件說明 |

## 7. 取捨

| 決策 | 選擇 | 放棄了什麼 | 理由 |
|---|---|---|---|
| 封鎖位置 | A 判斷並即時封鎖，B 在最外層丟棄 | B 的即時性；多一段 RouterOS 腳本 | A 可靠即時；B 省 conntrack 與容器負擔、撐過重啟；B 壞了 A 照常 |
| B 的通訊 | 路由器定期拉 JSON | 即時推送 | 容器不拿 RouterOS 帳密；失敗只會讓項目自然到期 |
| 事件種類 | 只有需要主動行為的 `bad_cookie`、`verify_fail`；SNI 與 `Host` 不符不算 | 慢速掃描器與盲掃來源的封鎖 | 寧可漏封；盲掃已在 TLS 或 `Host` 檢查被擋，不值得佔表格；`Host` 不符還可能是 HTTP/2 連線共用的真人 |
| `verify_fail` 分級 | 強訊號立即封，弱訊號 10 分鐘內 2 次 | 單一門檻的簡單 | 真人唯一會碰到的錯誤碼保留容錯，真正的 bot 一次就封 |
| 表滿 | 淘汰只剩紀錄的項目 | 完整保留所有累犯紀錄 | 確保最新的攻擊者仍會被封 |
| 計分 | 不計分，事件直接封鎖 | 調整敏感度的彈性 | 事件都很明確 |
| 封鎖狀態 | 閘門只存記憶體 | 閘門重啟後保留累犯紀錄 | 不寫磁碟；路由器端保留封鎖本身 |
| 參數 | 寫死常數 | 環境變數調整 | 沒有需求，需要時再加 |
| 檔案 | 單一 `main.go` | 模組化 | 保持「單檔反向代理」的定位 |
| 分享情報 | 不做（不回報 AbuseIPDB） | 聯防 | 單一閘門視野有限，誤報公開的風險大於效益 |

## 8. 使用者設定

| # | 項目 |
|---|---|
| U1 | 確認 DSM 憑證是 `*.ninja218j.myds.me` 萬用字元憑證；是的話走 DNS-01，不需要對外開 80，日後多網域也只要一張 |
| U2 | RB5009 開 WireGuard：閘門故障時能連回家修理；手機 App（DS File、Photos）也走這條 |
| U3 | 外部監控（UptimeRobot 等）檢查 `https://<網域>/__gate` 可連與憑證到期 |
| U4 | Split DNS：`/ip/dns/static add name=<網域> address=<NAS IP>`（會影響整個區網的解析） |
| U5 | 確認 `/system/ntp/client` 已啟用（RB5009 沒有時鐘電池，時間錯會讓 cookie 與憑證驗證失效） |
| U6 | DSM 排程：以 root 每天執行 `dsm-push-cert.sh`，勾選「僅在異常終止時寄信」 |
| U7 | DSM 把 `172.17.0.2` 加進受信任的 Proxy；關閉 QuickConnect 與 UPnP；Synology DDNS 不要開 IPv6 自動更新 |

## 9. 實作步驟

| # | 項目 | 驗收條件 |
|:-:|---|---|
| 1 | slog（§4.6） | 預設等級下，連續 100 個無 cookie 的 API 請求不產生任何日誌 |
| 2 | `cookieState`（§4.2） | 換 `GATE_KEY` 後帶舊 cookie：被導向驗證頁且 cookie 被清除，IP 未被封鎖 |
| 3 | `blocker` 與事件（§4.1、§4.3）；`Host` 檢查改為 421 | 錯誤 `Host`（含結尾 `.` 與大小寫的正規化）回 421 且不封鎖；全部 `__gate` 格式錯誤才封鎖，任一有效就放行；空 token 與偽造 token 第 1 次即封；`timeout-or-duplicate` 第 1 次不封、10 分鐘內第 2 次封；私有 IP 永不封鎖；favicon 與無 cookie 的 API 請求不產生事件；表滿時淘汰未封鎖的項目、全部封鎖中才拒絕新增；每小時一行表格大小 |
| 4 | `blockListener` 與累犯（§4.4） | 被封鎖的 IP 連線在 TLS 前被關閉；7 天內第 2 次 24 小時、第 3 次 7 天；`TRUST_CF_HEADER=1` 時改回 403 |
| 5 | 封鎖清單 JSON 與 `.rsc`（§4.5） | `/blocklist.json` 只列封鎖中的 IPv4、`ttl` 遞減；未設 `BLOCKLIST_LISTEN` 時不監聽；WAN 連不到 9090；路由器執行 script 後 `gate-block` 出現對應項目且 timeout 相符，該 IP 從 WAN 在 raw 被丟棄；停掉容器後既有項目照時效到期 |
| 6 | 第二層強化（§5） | 不帶或帶錯 `-servername` 的 `openssl s_client` 拿不到憑證、且不產生事件，正確網域正常；上游 IP 不回 SYN-ACK 時約 5 秒回 502；`/__gate` 帶三個標頭、轉發的回應不帶；`uses:` 全是 SHA |
| 7 | `gate_test.go` | `cookieState` 五種狀態與多個同名 cookie、`verify_fail` 強弱分級（siteverify 以 `httptest.Server` mock 各錯誤碼）、`Host` 正規化與 421、事件與封鎖時長（可注入 `now`）、表滿淘汰、私有 IP、`blockListener`、封鎖清單（只列封鎖中、`ttl` 正確、不含 IPv6）、嚴格 SNI 不產生事件 |
| 8 | 文件 | `docs/blocking.md`（事件、時長、防誤封、日誌、如何查詢與解除）；README（特色、`LOG_LEVEL`、`BLOCKLIST_LISTEN`、封鎖機制小節）；`docs/deploy-mikrotik.md`（方案 B、移除步驟、U2～U4）；`docs/security.md`（封鎖機制、換金鑰不會被封）；`docs/cert-sync-dsm.md`（U1、U6）；`CHANGES-blocking.md`（摘要、行為變更、環境變數、檔案異動、升級注意事項、驗證狀態） |

**選做（低優先）：** cookie 剩不到一半效期時自動續簽；路由器加 Spamhaus DROP 清單；誘餌登入頁（decoy.md）。

### 9.1 開發與驗證

```bash
gofmt -l . && go vet ./...
go test -race ./...
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o gate-arm64 .
```

- `go test -race` 需要 cgo（gcc）；Windows 本機沒有時跑 `go test ./...`，`-race` 交給 CI。
- Git Bash 會把 `/b/`、`next=/x` 這類以 `/` 開頭的參數與環境變數轉成 Windows 路徑；指令前加 `MSYS_NO_PATHCONV=1`。
- Git Bash 的 `sed -i` 會吃掉 CRLF；`main.go`、Dockerfile、README 是 CRLF，用編輯器或 `perl -pi` 修改，改完確認 CR 數與 LF 數相同。
- 驗證頁的 CSS 與 JavaScript 要在真的瀏覽器看；curl 測不出樣式錯誤。
- 本機端到端：`python -m http.server` 當假上游，閘門 `LISTEN=:8095`，以 `curl -H "Host: ..."` 模擬；模擬公網 IP 時暫開 `TRUST_CF_HEADER=1` 加 `CF-Connecting-IP`（走 handler 層，listener 層以單元測試覆蓋）；siteverify 用 `httptest.Server` mock。

## 10. 日後要重新檢視的地方

**封鎖機制上線後，依實際數據：**

- **`verify_fail` 誤封**：看強、弱訊號各自的錯誤碼分布與真人回報；弱訊號誤封明顯時改成只記錄，強訊號誤封則檢查驗證頁的送出流程（§4.1）。
- **表格大小長期接近上限**：壓縮結構（§4.3）。
- **B 的 1 分鐘延遲不夠**：被封鎖的 IP 在第一分鐘仍會打到閘門（由 A 擋下）；若造成負擔再縮短拉取間隔。
- **清單超過 `/tool/fetch` 能讀回的大小**：改成只輸出最近新增的項目，或分頁。
- **閘門升級頻繁、累犯紀錄常被清空**：把封鎖表定期寫到掛載的磁碟。
- **慢速掃描器成為困擾**：評估低權重事件，但要先有日誌證明不會誤封。
- **IPv6 流量明顯增加**：封鎖鍵改成 IPv6 `/64` 前綴。

**部署情況改變時：**

- **開放 port 80 或加入 HTTP→HTTPS 轉址**：加上 HSTS（`max-age=31536000`；轉發時刪掉 DSM 自己的 HSTS）。
- **驗證頁加入使用者輸入或第三方內容**：評估完整 CSP（內嵌 script 用 hash／nonce，列出 Turnstile 與字型來源）。
- **改用不在 public suffix list 上的自有網域**：評估 `__Host-gate` cookie（改名讓所有人重新驗證一次，`stripGateCookie` 兩個名稱都要移除）。
- **需要隱藏上游軟體**：在 `ModifyResponse` 刪除上游 `Server` 標頭。
- **驗證端點被慢速 body 佔住連線**：在 `verify` 用 `http.ResponseController` 設 10 秒讀取期限。

**CI：**

- **`ubuntu-latest` 換到新版後出問題**：把 `runs-on` 固定為 `ubuntu-24.04`。
- **新版 govulncheck 本身出錯**：暫時改回 `go install golang.org/x/vuln/cmd/govulncheck@<已知可用且支援目前 Go 的版本>`。
