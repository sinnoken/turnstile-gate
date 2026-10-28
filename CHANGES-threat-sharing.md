# 異動說明：威脅計分與情報分享

## 摘要

閘門會依來源 IP 的行為計分，超過門檻就在閘門內封鎖，並把封鎖結果分享到三個地方：

- **路由器**：從內網 port 拉取封鎖清單
- **日誌系統**：JSON 事件，可給 syslog、CrowdSec 等工具解析
- **AbuseIPDB**：選用，封鎖時回報

## 動機

閘門是自己維護的，沒有 Cloudflare 那種跨網站的威脅情報。不過閘門看得到每個 IP 的行為，把這些判斷結果輸出出去，可以帶來兩個好處：

1. 讓路由器在更外層直接丟棄已知的惡意 IP，減少閘門的負擔與攻擊面。
2. 與其他人共享，形成聯防。

## 行為變更

### 計分規則

| 事件 | 權重 | 觸發條件 |
|---|:-:|---|
| `bad_host` | 5 | `Host` 不在 `ALLOWED_HOSTS` 中（例如直接打 IP 的掃描器），回應 `404` |
| `bad_cookie` | 5 | `__gate` cookie 的簽章錯誤 |
| `verify_fail` | 3 | Turnstile token 被判定無效，包含空 token |
| `unauth` | 1 | 沒有 cookie 的非瀏覽器請求，例如直接打 API、掃 `/.env` |

- 在 `SCORE_WINDOW_MINUTES`（預設 10 分鐘）內累計達 `BLOCK_THRESHOLD`（預設 10 分），就封鎖 `BLOCK_MINUTES`（預設 60 分鐘）。
- 被封鎖的 IP，所有請求一律回應 `403`。這項檢查在最外層，比 Host 檢查和路由都早。

### 防誤封

| 情況 | 處理方式 |
|---|---|
| 通過驗證的 IP | 之後 `SESSION_HOURS + 24h` 內，`unauth` 不計分。DSM 在 cookie 過期後的背景請求會被回 `401`，這個機制避免因此誤封 |
| 簽章正確但已過期的 cookie | 不計分 |
| 私有、loopback、link-local IP | 不計分、不封鎖、不分享，只記錄日誌 |
| siteverify 連線失敗、`secret` 相關錯誤、`internal-error` | 不算訪客失敗 |
| 瀏覽器導覽（`GET` 且 `Accept` 含 `text/html`） | 照舊導向驗證頁，不計分 |

### 日誌格式

所有日誌改為 **一行一筆 JSON**，使用 `log/slog`，輸出到 stdout。原本 `log.Printf` 的訊息也會經由 slog 輸出成 JSON。

```json
{"time":"...","level":"INFO","msg":"gate","event":"unauth","ip":"203.0.113.50","method":"GET","path":"/.env","host":"nas.example.com","ua":"curl/8.5.0","score":3}
{"time":"...","level":"WARN","msg":"gate","event":"blocked","ip":"203.0.113.50","score":10,"minutes":60,"counts":{"unauth":10}}
```

事件種類：`unauth`、`verify_fail`、`bad_cookie`、`bad_host`、`blocked`、`feed_listen`、`feed_error`、`abuseipdb_report`、`abuseipdb_error`。

> ⚠️ 如果原本有依賴純文字日誌格式的解析規則，需要改寫。

## 新增環境變數

| 變數 | 預設 | 說明 |
|---|---|---|
| `ALLOWED_HOSTS` | 不檢查 | 允許的網域，以逗號分隔，不分大小寫，會去掉 port。建議設定 |
| `FEED_LISTEN` | 關閉 | 封鎖清單的監聽位址，例如 `:9100`。**不要對外開放** |
| `BLOCK_THRESHOLD` | `10` | 封鎖門檻分數 |
| `SCORE_WINDOW_MINUTES` | `10` | 計分視窗（分鐘） |
| `BLOCK_MINUTES` | `60` | 封鎖時間（分鐘） |
| `ABUSEIPDB_KEY` | 關閉 | 設定後，IP 被封鎖時會回報 AbuseIPDB |

## 新增端點（`FEED_LISTEN` 上）

| 路徑 | 回應 |
|---|---|
| `GET /blocklist` | `text/plain`，目前封鎖中的 IP，一行一個。依剩餘封鎖時間由長到短排序，最多 2000 筆 |
| `GET /healthz` | `ok` |

## AbuseIPDB 回報

- 只在 IP **剛被封鎖時**回報；同一個 IP 在 24 小時內不重複回報。回報以非同步方式送出，逾時 10 秒。
- 分類一律包含 `19`（Bad Web Bot），再依事件加上：

  | 事件 | 額外分類 |
  |---|---|
  | `unauth` 或 `bad_cookie` | `21`（Web App Attack） |
  | `verify_fail` | `18`（Brute-Force） |
  | `bad_host` | `14`（Port Scan） |

- 回報的註解只包含事件次數，**不會帶出自己的網域或路徑**。

## 檔案異動

| 檔案 | 異動 |
|---|---|
| `threat.go` | **新增**。計分器（`tracker`）、封鎖清單 feed、AbuseIPDB 回報、每分鐘清理過期資料 |
| `main.go` | 外層加上封鎖與 Host 檢查；以 `cookieState()` 取代 `validCookie()`，區分 none、valid、expired、forged 四種狀態；新增 `isBrowserNav()`；`siteverify()` 回傳值改為 `(ok, rejected, err)`；驗證成功時呼叫 `threats.passed()`；改用 slog 輸出 JSON 日誌 |
| `gate_test.go` | **新增**。測試 `safeNext`、`cookieState`、封鎖門檻、通過驗證者不因 401 被封、私有 IP 永不封鎖、Host 檢查端到端 |
| `Dockerfile` | `COPY go.mod main.go` 改為 `COPY go.mod *.go`，因為現在有多個原始檔 |
| `.dockerignore` | 改為放行 `*.go` |
| `.github/workflows/build.yml` | test job 新增 `go test -race ./...`，附上測試用環境變數 |
| `deploy/mikrotik-gate.rsc` | 新增 `domain` 變數；envs 新增 `ALLOWED_HOSTS`、`FEED_LISTEN`，`ABUSEIPDB_KEY` 為註解掉的選項；新增第 7 段：raw 丟棄規則、`gate-blocklist` 腳本、每分鐘執行的排程 |
| `docs/threat-sharing.md` | **新增**。計分規則、防誤封、三種分享方式、設定、限制 |
| `docs/deploy-mikrotik.md` | 變數範例新增 `domain`；建立項目表新增「封鎖清單同步」；移除指令新增 raw、address-list、scheduler、script |
| `README.md` | 特色新增「威脅分享」；新增「威脅計分與分享」章節與變數表；建置段落新增測試指令 |

## RouterOS 端（`mikrotik-gate.rsc` 第 7 段）

- `/ip/firewall/raw`：`prerouting` 鏈中，來自 WAN 且 `src-address-list=gate-block` 的封包直接丟棄。
- `/system/script gate-blocklist`：
  - 用 `/tool/fetch` 拉取 `http://172.17.0.2:9100/blocklist`。
  - 每一行以 `:toip` 驗證，**只接受合法的 IPv4，不執行清單內容**。
  - 不存在就新增到 `gate-block`，已存在就把 timeout 續成 `1h`。
  - 單次最多處理 2000 筆。
- `/system/scheduler gate-blocklist`：每 1 分鐘執行一次。
- 路由器端的 timeout 是 1 小時，所以閘門解除封鎖後，路由器最多還會再擋約 1 小時。

## 升級注意事項

1. **設定 `ALLOWED_HOSTS`**。沒設的話，`bad_host` 這個最準的訊號不會生效。
2. 如果閘門放在 Cloudflare Tunnel 或代理後方，必須設定 `TRUST_CF_HEADER=1`。否則所有請求的來源 IP 都會是 Cloudflare 或 Tunnel 的位址，可能誤封整個 Cloudflare 節點。
3. `FEED_LISTEN` 的 port 不可對外。MikroTik 範例只對外 NAT 了 443，所以這個 port 不會暴露。
4. 封鎖狀態只存在記憶體中，重啟後就清空；路由器 address-list 上的項目會保留到 timeout 為止。
5. 開啟 AbuseIPDB 之前，先觀察一段時間 `blocked` 事件，確認門檻合理。回報是公開的，誤報會影響共用同一個 IP 的其他人（行動網路、CGNAT）。

## 已知限制

- 最多同時追蹤 50,000 個 IP；超過後不再追蹤新 IP，已封鎖的 IP 不受影響。
- RouterOS 範例只同步 IPv4。閘門本身會記錄並封鎖 IPv6。
- 只有單一閘門的視野；真正的聯防需要 CrowdSec 或 AbuseIPDB 這類多方匯集的服務。
- 尚未提供 CrowdSec 的 parser 與 scenario。

## 驗證狀態

| 項目 | 狀態 |
|---|---|
| `go vet`、`gofmt` | ✅ |
| 單元測試（`go test -race`） | ✅ 全部通過 |
| 本機端到端：連續掃 10 個路徑 → 第 11 個請求回 `403` | ✅ |
| 本機端到端：用錯誤 Host 連 2 次 → 第 3 次回 `403` | ✅ |
| 本機端到端：私有 IP 大量錯誤 Host → 不封鎖、feed 為空 | ✅ |
| `/blocklist` 正確列出被封鎖的 IP | ✅ |
| JSON 事件格式 | ✅ |
| RouterOS 腳本在實機上執行 | ⏳ 未測（無 RouterOS 環境） |
| AbuseIPDB 實際回報 | ⏳ 未測（測試環境無外網） |
| GitHub Actions 實際執行 | ⏳ 未測（YAML 語法已確認） |
