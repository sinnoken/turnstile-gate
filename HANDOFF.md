# 交接文件：turnstile-gate

給接手的 agent。讀完這份文件就能繼續工作，不需要回頭看完整對話。

---

## 1. 專案是什麼

一支 Go 寫的單檔反向代理，放在 Synology DSM 前面，用 **Cloudflare Turnstile** 擋 bot。

```
網際網路 ─443─→ MikroTik RB5009（RouterOS v7，dst-nat）
                   └→ 容器 turnstile-gate 172.17.0.2:8443（TLS + Turnstile + HMAC cookie）
                         └─HTTPS─→ Synology DSM（內網 NAS:5001）
```

**運作流程：**
1. 沒有有效 cookie 的瀏覽器會被導到 `/__gate` 驗證頁。
2. 瀏覽器完成 Turnstile，把 token 送到 `POST /__gate/verify`。
3. 閘門在伺服器端呼叫 siteverify 確認 token，並比對 hostname。
4. 通過後發一個 HMAC 簽章 cookie `__gate`（格式 `<到期時間>.<簽章>`），之後的請求直接轉發給 DSM。

## 2. 使用者背景與偏好（重要）

- 家用環境：一台 Synology NAS、一台 **MikroTik RB5009**（arm64，RouterOS v7），容器跑在路由器上。
- DSM 網域使用 Synology DDNS，**前綴是 `dsm512.`，完整後綴還沒確認**（可能是 `dscloud.me`、`synology.me` 等）。
- **不經過 Cloudflare 代理或 Tunnel**，閘門直接對外，只有 Turnstile 會用到 Cloudflare。
- 憑證來自 DSM 的 Let's Encrypt，由 DSM 排程推送到路由器。
- 偏好：**輕量、精簡、有效**；不喜歡為了理論上的風險增加複雜度；重視實際數據。
- 已接受的判斷：
  - Turnstile 只擋 bot，不負責身分驗證。身分驗證交給 DSM 的密碼和 2FA。
  - **IPv6 先不處理**。使用者的實際紀錄顯示 IPv6 流量極少，就算 IPv6 位址公開，跟 IPv4 的差距也在千倍以上。
  - 不用 CrowdSec、Anubis、ALTCHA，目前的規模用不到。
  - 封鎖 1 小時對 bot 最有效，只封鎖「驗證沒過」的 IP。
- 文件一律用**繁體中文**（台灣用語）。

## 3. Repo 現況

位置：`/mnt/user-data/outputs/turnstile-gate/`（打包檔：`/mnt/user-data/outputs/turnstile-gate.zip`，**改完要重新打包**）

```
turnstile-gate/
├─ main.go                 閘門主程式：proxy、驗證頁、siteverify、cookie、憑證熱更新
├─ threat.go               計分、封鎖、/blocklist feed、AbuseIPDB（→ 大部分要刪）
├─ gate_test.go            單元測試（需要環境變數才能跑，見 §8）
├─ go.mod                  寫的是 go 1.22（→ 要改成 1.24）
├─ Dockerfile              scratch 映像，多架構，COPY go.mod *.go
├─ .dockerignore / .gitignore / LICENSE（MIT，擁有者標成 OWNER）
├─ .github/workflows/build.yml   test → GHCR 多架構映像 → RouterOS tar → tag 時發 Release
├─ deploy/
│   ├─ mikrotik-gate.rsc   RouterOS 設定：容器網路、NAT、防火牆、gatecert 帳號、容器、第 7 段 blocklist 腳本
│   ├─ dsm-push-cert.sh    DSM 推送憑證到路由器（hash 有變才推；--list 列出憑證）
│   └─ docker-compose.yml  給一般 Docker 主機用
└─ docs/
    ├─ deploy-mikrotik.md / cert-sync-dsm.md / security.md / threat-sharing.md
    └─ images/gate-{light,dark,error}.png
```

其他相關檔案：
- `/mnt/user-data/outputs/CHANGES-threat-sharing.md`：上一版（加入計分與分享）的異動說明
- `/mnt/user-data/outputs/turnstile-gate-review.md`：程式碼品質檢視
- `/mnt/user-data/outputs/turnstile-gate-blindspots.md`：架構盲點檢視

所有 `OWNER` 都是佔位符，要換成使用者的 GitHub 帳號。

## 4. 已知 bug

| # | 位置 | 問題 |
|---|---|---|
| B1 | `mikrotik-gate.rsc` 第 4 段 input drop | 沒有加 `connection-state=new`，容器回給路由器的封包會被擋掉，路由器拉不到 `/blocklist` |
| B2 | `main.go` 的 `unauth` 計分 | 瀏覽器自動請求 favicon、手機切換網路時 DSM 背景請求被 401，都會讓真人被誤封 |
| B3 | `cookieState` 回傳 `cookieForged` 的時機 | 換 `GATE_KEY` 後，所有合法 cookie 都會被當成偽造並封鎖 |
| B4 | 憑證續期 | DSM 若用 HTTP-01 驗證就需要外部連得到 80 port，但目前只轉發 443。**如果是 Synology DDNS 的萬用字元憑證，走的是 DNS-01，不需要 80**（需要使用者確認） |

## 5. 待使用者決定（開工前先問）

**D1：封鎖要在哪裡做？** 這是唯一還沒定案的事。

| | A. 閘門自己封鎖（**建議**） | B. 通知路由器 |
|---|---|---|
| 做法 | 收到三種事件時把 IP 存進記憶體，封鎖 1 小時；用自訂的 `net.Listener`，在 `Accept()` 時遇到被封鎖的 IP 就直接 `Close()`，TLS 握手都不做 | 閘門提供 `GET /events?since=N`（事件編號、IP、事件類型），RouterOS 每 30 秒拉一次，寫進 address-list，用 raw 規則丟棄 |
| 程式量 | Go 約 40 行 | Go 約 60 行，加上 RouterOS 腳本約 50 行 |
| 容易壞的地方 | 幾乎沒有 | 防火牆規則（B1）、腳本解析、RouterOS 版本差異 |
| 累犯加重 | 用一個 Go map 就能做 | RouterOS 腳本做起來很複雜 |

使用者原本的想法是「把失敗通知路由器，由路由器決定怎麼處理」。助理評估後建議 A，理由是更有效也更精簡，但使用者**還沒回覆**。選 B 的話，先只做最簡單的版本（不含累犯加重），並修掉 B1。

**D2：DSM 網域的完整後綴？** 會用來填 `ALLOWED_HOSTS` 和 `.rsc` 裡的 `domain`。

## 6. 要做的事

### 6.1 程式改動（agent 負責）

| # | 項目 | 驗收條件 |
|---|---|---|
| T1 | **只保留三種事件**：`bad_host`（Host 不在 `ALLOWED_HOSTS`）、`bad_cookie`（格式錯誤的 cookie）、`verify_fail`（Turnstile token 被判定無效）。**完全拿掉 `unauth`** | 沒有 cookie 的 API 請求、favicon 請求都不會觸發任何事件 |
| T2 | **cookie 簽章不符時**：回一個已過期的 `Set-Cookie` 讓瀏覽器刪掉，再導回驗證頁（非瀏覽器請求回 401），**不算事件**。只有格式根本不對的 cookie（沒有 `.`、到期時間不是數字）才算 `bad_cookie`。也可以考慮在 cookie 裡加金鑰版本號 | 更換 `GATE_KEY` 後，舊 cookie 只會讓使用者重新驗證一次，不會被封鎖 |
| T3 | `verify_fail`：**第一次只記錄，10 分鐘內第二次才封鎖**。連不到 Cloudflare、secret 錯誤、`internal-error` 都不算事件（現有邏輯保留） | 使用者重新整理或按上一頁時偶爾失敗一次，不會被封鎖 |
| T4 | 依 D1 實作封鎖：**A**：在 listener 層封鎖 1 小時，加上累犯加重（7 天內第二次 24 小時，第三次以上 7 天）；**B**：見 §5 | 被封鎖的 IP 在 A 方案下連 TLS 握手都不會發生 |
| T5 | **刪除** `/blocklist`、`FEED_LISTEN`（A 方案）、AbuseIPDB、`BLOCK_THRESHOLD` 和 `SCORE_WINDOW_MINUTES` 計分機制 | `threat.go` 大幅縮小，或併進 `main.go` |
| T6 | 日誌：預設只記錄錯誤、封鎖、事件；`LOG_LEVEL=debug` 才逐筆記錄。維持 JSON 格式 | 被掃描時不會洗掉 RouterOS 的 `/log` |
| T7 | 新增 `UPSTREAM_SERVER_NAME`：用內網 IP 連線，但用網域名稱驗證 DSM 的憑證。設了這個就不需要 `UPSTREAM_INSECURE` | 設定網域名稱後，憑證驗證可以通過 |
| T8 | `verify()` 的 body 加上 `http.MaxBytesReader`，上限 4KB | 送大 body 會被拒絕 |
| T9 | 所有回應加上 `Strict-Transport-Security: max-age=31536000` | |
| T10 | `go.mod` 改成 `go 1.24` | CI 和 Dockerfile 用同一個版本 |
| T11 | 設定改在 `main()` 裡用 `loadConfig()` 讀取，不要在 package `var` 初始化時讀 | 測試不需要設環境變數 |
| T12 | workflow 加上每週排程重新建置（`schedule: cron`），test job 加 `govulncheck` | |
| T13 | `.rsc`：加入 `GOMEMLIMIT=48MiB` 環境變數；拿掉 AbuseIPDB 那行；依 D1 處理第 7 段（A 方案整段刪除，raw 規則也刪；B 方案改寫並修 B1）；更新 envs | |
| T14 | 更新文件：README 的環境變數表、`docs/threat-sharing.md`（A 方案可以刪掉，或改寫成「封鎖機制」）、`deploy-mikrotik.md`、`security.md`；`cert-sync-dsm.md` 補上「排程只在異常終止時寄信」的設定 | 文件和程式一致 |
| T15 | 寫新的 `CHANGES-*.md`（格式參考 `CHANGES-threat-sharing.md`），重新打包 zip | |

**選做（使用者沒有要求，優先度低）：** cookie 剩不到一半效期時自動續簽；路由器加 Spamhaus DROP 黑名單。

### 6.2 使用者自己設定（寫進文件，或提醒使用者）

| # | 項目 |
|---|---|
| U1 | 確認 DSM 憑證是 `*.dsm512.xxx` 萬用字元憑證（關係到 B4） |
| U2 | RB5009 開 WireGuard：閘門故障時能連回家修理，手機 App（DS File、Photos）也走這條 |
| U3 | 外部監控（UptimeRobot 等），檢查 `https://<網域>/__gate` 能不能連、憑證何時到期 |
| U4 | Split DNS：`/ip/dns/static add name=<網域> address=<NAS IP>` |
| U5 | 確認 `/system/ntp/client` 已啟用（RB5009 沒有時鐘電池） |
| U6 | DSM 排程：以 root 每天執行 `dsm-push-cert.sh`，勾選「僅在異常終止時寄信」 |
| U7 | DSM 把 `172.17.0.2` 加進受信任的 Proxy；關閉 QuickConnect 和 UPnP；Synology DDNS 不要開 IPv6 自動更新 |

## 7. 不要做的事

- 不要重新加回 `unauth` 這類「真人也會觸發」的計分。
- 不要讓容器拿到 RouterOS 的 API 帳密。RouterOS 的權限沒辦法只開放 address-list，給了就等於能改整台路由器。
- 不要把 DSM 的 80 或 5000/5001 直接轉發到外部，會繞過閘門。
- 不要在直接對外時預設開啟 `TRUST_CF_HEADER`，會讓攻擊者能偽造來源 IP。
- 不要引入第三方 Go 套件，維持只用標準函式庫、單一執行檔。
- 不要為 IPv6 加任何機制。

## 8. 開發與驗證

```bash
cd /mnt/user-data/outputs/turnstile-gate
gofmt -l . && go vet ./...
# T11 改完之前，跑測試需要環境變數：
TURNSTILE_SITEKEY=x TURNSTILE_SECRET=x GATE_KEY=k UPSTREAM=http://127.0.0.1:1 go test -race ./...
CGO_ENABLED=0 GOARCH=arm64 go build -ldflags="-s -w" -o /tmp/gate .
```

本機端到端測試的做法：用 Python 起一個假的上游（`http.server`），閘門用 `LISTEN=:8095` 啟動，再用 curl 帶 `Host:` 標頭模擬請求。要模擬公網 IP，可以暫時開 `TRUST_CF_HEADER=1` 搭配 `CF-Connecting-IP`。

**環境限制：**
- 連不到 `challenges.cloudflare.com`，siteverify 只能用 mock 或跳過。
- 沒有 Docker daemon，也沒有 RouterOS。
- 用 `go run` 抓外部工具（例如 actionlint）會被權限擋下。
- 結束測試用的程序時，用 `pkill -x gate`。**不要用 `pkill -f ./gate`**，會連當前的 shell 一起砍掉。

**目前驗證狀態：** 單元測試、vet、gofmt 都通過；本機端到端測試過封鎖、feed、HTTPS、憑證熱更新。**沒有驗證過**：真實的 siteverify、RouterOS 匯入與腳本、GitHub Actions 實際執行、AbuseIPDB。

## 9. 開工順序

1. 問使用者 **D1**（建議 A）和 **D2**（網域後綴）。
2. 修 B2、B3 → T1、T2、T3。
3. T4、T5（依 D1）。
4. T6 到 T12。
5. T13、T14：`.rsc` 和文件。
6. 測試 → T15：寫 `CHANGES`、重新打包。
7. 回覆使用者時列出 U1 到 U7 的提醒，以及哪些部分還沒在實機上驗證。
