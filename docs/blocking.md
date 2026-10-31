# 封鎖機制

閘門只封鎖「**確定不是真人**」的 IP：對方必須主動做出某件真人不會做的事。原則是**寧可漏封，不要誤封**；盲掃與送錯網域的雜訊交給嚴格 SNI、`Host` 檢查與路由器速率限制，不佔封鎖表。

## 什麼會被封鎖

| 事件 | 觸發條件 | 處理 | 為什麼真人不會觸發 |
|---|---|---|---|
| `bad_cookie` | 請求帶的**所有** `__gate` cookie 都格式錯誤：沒有 `.`、到期時間不是數字、簽章不是 64 字元 hex | 立即封鎖，回 `403` | 閘門發的 cookie 格式永遠正確，換 `GATE_KEY` 也不變 |
| `verify_fail`（`signal=strong`） | token 為空（`empty-token`）；siteverify 錯誤碼 `invalid-input-response`、`bad-request`；token 的 hostname 不符（`hostname-mismatch`） | 立即封鎖 | 驗證頁只在 Turnstile 通過後才自動送出表單，真人送出的一定有 token；其他是偽造或拿別的網站產生的 token |
| `verify_fail`（`signal=weak`） | siteverify 錯誤碼 `timeout-or-duplicate` | 10 分鐘內第 1 次只記錄，第 2 次才封鎖 | token 超過 5 分鐘或重複送出（按上一頁）偶爾會發生，但不會連續發生 |

多個同名 `__gate` cookie 時，任一個有效就放行；只要有一個是過期或簽章不符，就當成「重新驗證」處理；**全部都格式錯誤**才算 `bad_cookie`。

## 什麼不會被封鎖

| 情況 | 處理 | 理由 |
|---|---|---|
| SNI 不在 `ALLOWED_HOSTS`（HTTPS 模式，沒帶 SNI 也算） | 中斷 TLS 握手、不送出憑證；只在 `debug` 記錄 | 用 IP 盲掃的掃描器來源很多，握手階段就拿不到任何東西；封鎖它們只會讓表格變大、讓 CGNAT 後的真人更容易被連帶封鎖 |
| `Host` 不在 `ALLOWED_HOSTS` | 回 `421 Misdirected Request`；只在 `debug` 記錄 | 多半是 HTTP/2 連線共用（瀏覽器把同一 IP、同一張憑證的不同網域放在同一條連線），`421` 讓瀏覽器另開連線重試 |
| siteverify 錯誤碼 `missing-input-secret`、`invalid-input-secret`、`internal-error`，或連不上 Cloudflare | `error` 記錄 | 閘門設定錯誤或 Cloudflare 的問題，不是使用者的錯 |
| cookie 簽章不符（換了 `GATE_KEY`）或已過期 | 清除 cookie，導向驗證頁或回 `401` | 換金鑰後所有人重新驗證一次，**不會被封** |
| 沒有 cookie（含空值 `__gate=`）的請求、favicon、DSM 背景 API | 不記錄 | 真人也會產生 |

Turnstile 元件端的錯誤（例如 `110200` 網域未授權）不會產生 token、也不會送出表單，不會變成事件。

## 封鎖時長

| 7 天內第幾次 | 時長 |
|:-:|---|
| 1 | 1 小時 |
| 2 | 24 小時 |
| ≥ 3 | 7 天 |

- 7 天視窗以「最後一次被封鎖」起算：距離上次封鎖超過 7 天，次數歸零。
- 封鎖期間再觸發事件不會重複加重。
- 觸發封鎖的那次 `verify_fail` 仍照常導回驗證頁（`?err=1`）並關閉連線，封鎖從下一個請求／連線開始生效。
- **私有、loopback、link-local IP 永不封鎖**（例如 `192.168.x.x`、`10.x.x.x`、`172.16.x.x`～`172.31.x.x`、`127.0.0.1`、`169.254.x.x`）：事件照樣記錄，只是不封。從家裡用內網連線測試不會把自己鎖在外面。CGNAT 位址（`100.64.0.0/10`）不在此列。
- 閘門端（A）IPv4、IPv6 都會封鎖；`/blocklist.json` 只列 IPv4，路由器端（B）只處理 IPv4。
- 門檻與時長寫死在程式常數，不開環境變數。

## 兩層封鎖

| | 閘門（A） | 路由器（B，選用） |
|---|---|---|
| 角色 | **判斷者**：事件、累犯、時長都在這裡決定 | **執行者**：只照清單丟封包 |
| 做法 | 被封鎖的 IP 在 `Accept()` 時直接關閉連線，不做 TLS 握手；觸發封鎖的那條 keep-alive 連線回 `403` 並關閉 | 每分鐘拉 `/blocklist.json`，寫進有時效的 address-list `gate-block`，raw prerouting 丟棄 |
| 生效 | 事件當下 | 最多延遲約 1 分鐘 |
| 閘門重啟 | 封鎖表清空（只存在記憶體） | address-list 項目照 timeout 保留 |

B 壞了（腳本錯、閘門沒回應）A 照常運作；address-list 項目都有 timeout，拉不到新清單只會自然到期，不會留下永久封鎖。路由器不需要給容器任何 RouterOS 帳密。路由器端設定見 [deploy-mikrotik.md](deploy-mikrotik.md#封鎖清單路由器端)。

### 封鎖表上限

- 封鎖表上限 50,000 筆（約 10～12 MB，在 `GOMEMLIMIT=48MiB` 內）。SNI 與 `Host` 不符都不入表，正常情況遠低於上限。
- 表滿時要新增 IP：先淘汰一筆「沒在封鎖、只剩累犯或 `verify_fail` 紀錄」的項目（最久沒被封的優先）；全部都在封鎖中才放棄新增，並記一行 `table full` warn；之後到最早一筆解封前都直接放棄，不再掃描、也不再記錄。確保最新的攻擊者仍會被封。
- 每 10 分鐘清掉已過期的項目；每小時記一行 `table` 日誌（總筆數、封鎖中筆數），長期接近上限時再調整。

## 封鎖清單 JSON

設定 `BLOCKLIST_LISTEN`（例：`172.17.0.2:9090`；變數說明見 [README 設定](../README.md#設定)）才啟用，沒設就不監聽。

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

RouterOS `/tool/fetch output=user` 最多讀回 64512 bytes（63 KiB），超過的部分**直接截斷、不報錯**（RouterOS 手冊 `/tool/fetch` 與 Fetch 指南）。因此清單上限 800 筆（程式常數 `blocklistMax`；每筆最長約 72 bytes，800 筆約 58 KB），超過時只輸出 `ttl` 最長的前 800 筆，並記一行 `blocklist truncated` warn（欄位 `items`、`max`）。非 GET 回 `405`，其他路徑回 `404`；沒有封鎖中的 IP 時 `items` 是空陣列 `[]`。

## 日誌

等級由 `LOG_LEVEL` 設定（見 [README 設定](../README.md#設定)）。JSON 格式（`log/slog`）輸出到 stdout，RouterOS 會寫進 `/log`（`topics~"container"`）。每個欄位有名稱，使用者字串會自動跳脫；不記錄 cookie 值與 token。

| `LOG_LEVEL` | 記錄什麼 |
|---|---|
| `debug` | 每筆請求（`request`）、listener 丟棄的連線（`dropped`）、SNI 不符的握手（`sni rejected`）、其他 TLS 握手失敗（`http: TLS handshake error ...`）、`Host` 不符（`misdirected`） |
| `info`（預設） | 事件（`event`）、啟動（`start`、`blocklist`）、關閉（`shutdown`）、憑證載入（`certificate loaded`）、每小時一行表格大小（`table`） |
| `warn` | 封鎖（`blocked`，`duration` 為 `1h0m0s`、`24h0m0s`、`168h0m0s`）、表滿無法新增（`table full`）、封鎖清單被截斷（`blocklist truncated`）、同時設了 `UPSTREAM_SERVER_NAME` 與 `UPSTREAM_INSECURE`（`UPSTREAM_SERVER_NAME 已設定，忽略 UPSTREAM_INSECURE`） |
| `error` | siteverify 連線或設定錯誤（`siteverify`）、上游錯誤（`upstream`；用戶端自己中斷的只記 `debug`）、憑證重新載入失敗（`reload cert failed, keep old`）、啟動失敗後結束（`config`、`listen`、`load cert`、`blocklist listen`、`blocklist serve`、`serve`，原因在 `err` 欄位） |

預設等級下被掃描也不會洗掉 `/log`：沒有 cookie 的請求、SNI 與 `Host` 不符都不記錄。`debug` 只在排查問題時短暫開啟。

```json
{"time":"...","level":"INFO","msg":"event","event":"verify_fail","signal":"weak","ip":"203.0.113.50","host":"nas.example.com","ua":"...","errors":["timeout-or-duplicate"]}
{"time":"...","level":"WARN","msg":"blocked","ip":"203.0.113.50","event":"verify_fail","signal":"strong","strike":2,"duration":"24h0m0s"}
{"time":"...","level":"INFO","msg":"table","entries":184,"blocked":37}
{"time":"...","level":"ERROR","msg":"siteverify","err":"context deadline exceeded"}
```

## 查詢誰被封鎖

```
# 閘門日誌：事件與封鎖
/log/print where topics~"container" message~"\"msg\":\"(event|blocked)\""

# 路由器端 address-list（comment 是 gate: <事件> #<次數>）
/ip/firewall/address-list/print where list=gate-block

# 直接看閘門的清單（只在路由器上執行；9090 不對其他主機開放）
:put ([/tool/fetch url="http://172.17.0.2:9090/blocklist.json" output=user as-value]->"data")
```

一般 Docker 主機：`docker logs turnstile-gate 2>&1 | grep -E '"msg":"(event|blocked)"'`。

## 解除封鎖（誤封時）

兩層都要處理：

1. **閘門端**：重啟容器即清空封鎖表（累犯次數也一併歸零）。

   ```
   /container/stop [find comment="gate"]
   /container/start [find comment="gate"]
   ```

2. **路由器端**：刪掉 address-list 項目，否則下一輪之前仍會在 raw 被丟棄。

   ```
   /ip/firewall/address-list/remove [find list=gate-block address=203.0.113.50]
   # 全部清掉
   /ip/firewall/address-list/remove [find list=gate-block]
   ```

順序：先重啟閘門再刪路由器項目；反過來的話，路由器下一分鐘會從閘門重新拉回來。

## TRUST_CF_HEADER

`TRUST_CF_HEADER=1`（變數說明見 [README 設定](../README.md#設定)）時，TCP 連線來源是 Cloudflare 節點，封它等於封所有人。因此：

- listener 層**不封鎖**，改由 handler 依 `CF-Connecting-IP` 判斷，封鎖中的 IP 回 `403`。
- 路由器看到的來源也是 Cloudflare 節點，清單裡的真實 IP 不會直接連到路由器，路由器端封鎖沒有作用，不需要設定。

直接對外時不要開 `TRUST_CF_HEADER`：攻擊者可以偽造 `CF-Connecting-IP`，把別人的 IP 送進封鎖表、用大量假 IP 塞滿封鎖表，或填私有 IP 躲開封鎖。
