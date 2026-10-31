# 開發計畫：turnstile-gate

閘門目前的行為：封鎖機制見 [docs/blocking.md](../blocking.md)，功能與環境變數見 [README](../../README.md)，部署見 [docs/deploy-mikrotik.md](../deploy-mikrotik.md)。誘餌登入頁（選做）見 [decoy.md](decoy.md)。

## 1. 範圍

| 項目 | 內容 | 章節 |
|---|---|---|
| 路由器端驗收 | 在 RB5009 上確認封鎖清單（B）與部署設定 | §3 |
| 上線後檢視 | 依正式環境的日誌決定要不要調整封鎖機制 | §4 |
| 條件觸發的項目 | 部署情況或 CI 改變時才做 | §5 |
| 選做 | cookie 自動續簽、Spamhaus DROP、誘餌登入頁 | §6 |

---

## 2. 背景與限制

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

### 2.1 原則

- **輕量、精簡、有效**；不為理論風險增加複雜度；依實際數據調整。
- Turnstile 只擋 bot，不負責身分驗證；身分驗證交給 DSM 的密碼與 2FA。
- **寧可漏封，不要誤封**：只封鎖「確定不是真人」的 IP。
- 封鎖表只放**主動做出某件事**的 IP；盲掃與送錯網域的雜訊交給嚴格 SNI、`Host` 檢查與路由器限速。
- 門檻、時長、上限寫死在常數，不開環境變數。
- 不用 CrowdSec、Anubis、ALTCHA、AbuseIPDB。
- 文件一律用 **繁體中文**（台灣用語）。

### 2.2 不要做的事

- 不要加入「真人也會觸發」的事件（例如沒有 cookie 的請求）。
- 不要讓容器拿到 RouterOS 的 API 帳密（RouterOS 無法只開放 address-list）。
- 不要把 DSM 的 80、5000、5001 直接轉發到外部，會繞過閘門。
- 不要在直接對外時預設開啟 `TRUST_CF_HEADER`，會讓攻擊者偽造來源 IP。
- 不要引入第三方 Go 套件；維持標準函式庫、單一 `main.go`、單一執行檔（CI 工具如 `govulncheck` 不算相依套件）。
- 不要為 IPv6 加任何機制。
- 不要改 cookie 格式而不保留過渡期：舊格式必須判為 `badsig`（清除、不算事件），至少保留一個 `SESSION_HOURS`，否則所有人的舊 cookie 都會被當成 `malformed` 而集體封鎖。

## 3. 路由器端驗收

部署方式照 [docs/deploy-mikrotik.md](../deploy-mikrotik.md)「已部署的路由器加上封鎖清單」：`stop` → 加 `BLOCKLIST_LISTEN` → `repull` → `start`，再加入 script、scheduler、raw 規則。

### 3.1 封鎖清單（B）

測試用的被封鎖 IP：從外部網路（例如手機行動網路）帶格式錯誤的 cookie 打一次，例如 `curl -H "Cookie: __gate=x" https://<網域>/`，回 `403` 後該 IP 封鎖 1 小時。

| # | 驗收條件 |
|:-:|---|
| 1 | `/system/script/print` 的 `gate-blocklist` source 與 `.rsc` 一致（`/import` 沒有吃掉內層的 `{ }`） |
| 2 | 1 分鐘內 `gate-block` 出現該 IP；`timeout` 與 `/blocklist.json` 的 `ttl` 相符（確認 `:totime` 的轉換）；comment 為 `gate: bad_cookie #1` |
| 3 | 再跑一輪 script，同一 IP 只更新 `timeout`、不重複新增（`find address=$ip` 比對得到 `:deserialize` 產生的值） |
| 4 | 該 IP 從 WAN 連線在 raw 被丟棄（raw 規則的封包計數增加，閘門沒有 `dropped` 記錄） |
| 5 | 從 WAN 連不到 9090 |
| 6 | 停掉容器後，fetch 失敗只記一行 warning，既有項目照 timeout 到期 |
| 7 | 正常運作時每分鐘的 fetch 不在 `/log` 留下 info 雜訊；有的話調整 script 或 logging 規則 |
| 8 | scheduler、raw 規則的 `comment` 都有寫入 |
| 9 | 照 [docs/blocking.md](../blocking.md)「解除封鎖」解除測試 IP 後，該 IP 能正常打開驗證頁 |

### 3.2 部署設定

照 [docs/deploy-mikrotik.md](../deploy-mikrotik.md)「DSM 端設定」「建議設定」與 [docs/cert-sync-dsm.md](../cert-sync-dsm.md) 確認：

| # | 項目 |
|:-:|---|
| 1 | DSM 憑證是 `*.ninja218j.myds.me` 萬用字元憑證並列出網域本身；走 DNS-01，不對外開 80 |
| 2 | DSM 排程以 root 每天執行 `dsm-push-cert.sh`，只在異常終止時寄信 |
| 3 | DSM 把 `172.17.0.2` 加進受信任的 Proxy；QuickConnect、UPnP 關閉；Synology DDNS 不開 IPv6 自動更新 |
| 4 | RB5009 的 WireGuard 可連回家；手機 App（DS File、Photos）走這條 |
| 5 | 外部監控（UptimeRobot 等）檢查 `https://<網域>/__gate` 可連與憑證到期 |
| 6 | Split DNS：`/ip/dns/static` 有 `<網域>` → NAS IP |
| 7 | `/system/ntp/client` 已啟用 |
| 8 | `/container/repull remote-image=...:<版本>` 後看容器的 `remote-image`：被改寫成該版本時，[docs/deploy-mikrotik.md](../deploy-mikrotik.md)「更新映像」寫明之後要指定 `:latest` |

驗收：以上全部確認；結果與文件不符的地方改文件或 `deploy/`。

## 4. 上線後檢視

以預設 `LOG_LEVEL=info` 跑兩週後，從 `/log` 統計 `event`、`blocked`、`table` 日誌（查詢方式見 [docs/blocking.md](../blocking.md)「查詢誰被封鎖」），逐項決定：

| 項目 | 看什麼 | 判斷與做法 |
|---|---|---|
| `verify_fail` 誤封 | `signal`、`errors` 的分布與真人回報 | Cloudflare 文件把 `invalid-input-response` 寫成「invalid or has expired」：若真人的過期 token 會回這個碼，改列為弱訊號。弱訊號誤封明顯時改成只記錄。強訊號其他碼誤封時檢查驗證頁的送出流程 |
| 表格大小 | 每小時 `table` 的 `entries` | 長期接近 50,000 時壓小結構：key 改用 `uint32` 存 IPv4、時間改用 `uint32` 秒，每筆約 40～50 bytes |
| 清單截斷 | `blocklist truncated` warn | 常出現時改成只輸出最近新增的項目，或分頁拉取 |
| B 的延遲 | 被封鎖 IP 在第一分鐘的 `dropped`（需短暫開 `debug`） | 造成負擔才縮短拉取間隔 |
| 累犯紀錄被清空 | 閘門重啟頻率 | 升級頻繁、累犯常被清空時，把封鎖表定期寫到掛載的磁碟 |
| 慢速掃描器 | 未封鎖但反覆出現的來源 | 先有日誌證明不會誤封，才評估低權重事件 |
| IPv6 | IPv6 來源的事件比例 | 明顯增加時，封鎖鍵改成 IPv6 `/64` 前綴 |

驗收：每一項有結論（維持或改），要改的寫成本文件的新項目。

## 5. 條件觸發的項目

| 條件 | 做法 |
|---|---|
| 開放 port 80 或加入 HTTP→HTTPS 轉址 | 加上 HSTS（`max-age=31536000`）；轉發時刪掉 DSM 自己的 HSTS |
| 驗證頁加入使用者輸入或第三方內容 | 完整 CSP：內嵌 script 用 hash 或 nonce，列出 Turnstile 與字型來源 |
| 改用不在 public suffix list 上的自有網域 | cookie 改名 `__Host-gate`（所有人重新驗證一次），`stripGateCookie` 兩個名稱都移除 |
| 需要隱藏上游軟體 | 在 `ModifyResponse` 刪除上游 `Server` 標頭 |
| 驗證端點被慢速 body 佔住連線 | 在 `verify` 用 `http.ResponseController` 設 10 秒讀取期限 |
| `ubuntu-latest` 換到新版後 CI 出問題 | `runs-on` 固定為 `ubuntu-24.04` |
| 新版 govulncheck 本身出錯 | 暫時改回 `go install golang.org/x/vuln/cmd/govulncheck@<已知可用且支援目前 Go 的版本>` |

## 6. 選做（低優先）

| 項目 | 做法 | 驗收條件 |
|---|---|---|
| cookie 自動續簽 | 有效 cookie 剩不到一半效期時，在轉發的回應加上新的 `Set-Cookie`（同 `SESSION_HOURS`） | 剩餘效期過半的請求不續簽；不到一半時回應帶新 cookie，上游的 `Set-Cookie` 不受影響 |
| Spamhaus DROP | 路由器排程定期拉 DROP 清單寫進有時效的 address-list，raw prerouting 丟棄；閘門不參與 | 清單中的 IP 從 WAN 在 raw 被丟棄；拉取失敗時既有項目照時效到期 |
| 誘餌登入頁 | 見 [decoy.md](decoy.md) | 見 decoy.md §5 |

## 7. 開發與驗證

```bash
gofmt -l . && go vet ./...
go test -race ./...
CGO_ENABLED=0 GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o gate-arm64 .
```

- `go test` 不需要任何環境變數；時間可注入，siteverify 用 `httptest.Server` mock。
- `go test -race` 需要 cgo（gcc）；Windows 本機沒有時跑 `go test ./...`，`-race` 交給 CI。
- Git Bash 會把 `/b/`、`next=/x` 這類以 `/` 開頭的參數與環境變數轉成 Windows 路徑；指令前加 `MSYS_NO_PATHCONV=1`。
- Git Bash 的 `sed -i` 會吃掉 CRLF；`main.go`、Dockerfile、README 是 CRLF，用編輯器或 `perl -pi` 修改，改完確認 CR 數與 LF 數相同。
- 驗證頁的 CSS 與 JavaScript 要在真的瀏覽器看；curl 測不出樣式錯誤。
- 本機端到端：`python -m http.server` 當假上游，閘門 `LISTEN=:8095`，以 `curl -H "Host: ..."` 模擬；模擬公網 IP 時暫開 `TRUST_CF_HEADER=1` 加 `CF-Connecting-IP`（走 handler 層，listener 層以單元測試覆蓋）。
- RouterOS 指令用 7.24+ 語法，寫之前對照官方手冊。
