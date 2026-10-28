# 安全模型與 FAQ

## turnstile-gate 擋什麼、不擋什麼

| 威脅 | 結果 | 說明 |
|---|:-:|---|
| 大量掃描、撞庫、暴力破解的 bot | ✅ | 主要用途 |
| 自動化攻擊後端服務的漏洞 | ✅ 大多 | 後端不對外，未通過驗證的請求碰不到。過去 DeadBolt、eCh0raix 等 NAS 勒索軟體都靠大規模掃描對外開放的 NAS |
| 真實瀏覽器 + AI／付費代解 | ⚠️ | Turnstile 能被代解，刻意針對你的人可以通過 |
| 通過驗證後的後端漏洞 | ❌ | 靠更新後端 |
| DDoS | ❌ | 閘門直接對外，頻寬會被塞滿 |
| 帳密被釣魚 | ❌ | 靠 2FA |
| 內網電腦中毒，透過 SMB 加密 NAS | ❌ | 不經過閘門 |
| 其他入口（QuickConnect、UPnP 開的 port） | ❌ | 會繞過閘門，請關閉 |

**一句話：Turnstile 判斷「是不是人」，不判斷「是不是你」。** 身分驗證交給後端的密碼與 2FA。

## 建議的防護組合

| 層級 | 擋什麼 | 優先度 |
|---|---|---|
| 只對外開一個 port | 掃描其他服務 | 必要 |
| turnstile-gate | 自動化 bot | 必要 |
| 後端 2FA、停用預設管理員、自動封鎖 | 真人 / 帳密外洩 | 必要 |
| 快照（可設不可變）＋ 異地備份 | 以上全部失守、勒索軟體 | 必要 |
| 路由器速率限制 | 灌爆閘門 | 建議 |
| 容器網路隔離 | 閘門本身被攻破 | 建議（尤其跑在路由器上） |
| Cloudflare 代理 / Tunnel | DDoS、隱藏 IP | 選用 |
| 不對外，改用 Tailscale / VPN | 幾乎全部 | 只有自己人使用時最佳 |

## 設計上的安全細節

- **一定在伺服器端驗證**：token 交給 `siteverify` 驗證，並比對回傳的 `hostname`，別的網站產生的 token 不能用。
- **cookie 防偽造**：`<到期時間>.<HMAC-SHA256>`，以 `GATE_KEY` 簽章、constant-time 比對。
- **cookie 屬性**：`HttpOnly`、`Secure`、`SameSite=Lax`；不轉送給後端。
- **防 open redirect**：`next` 只接受站內相對路徑，`//evil.com` 等一律改成 `/`。
- **IP 來源**：預設使用 TCP 連線位址。`CF-Connecting-IP` 只在 `TRUST_CF_HEADER=1` 時採用，避免直接對外時被偽造。
- **最小映像**：`scratch` 底，只有執行檔與 CA 憑證，以非 root（UID 65534）執行。

## FAQ

### 為什麼不直接把 Turnstile 塞進 DSM 登入頁？

Turnstile 分兩半：前端元件產生 token，**後端必須拿 token 去驗證**。DSM 的登入 API（`/webapi/entry.cgi`）是 Synology 寫死的，不會驗證 token；就算改了前端頁面，bot 直接打 API 就繞過了，而且 DSM 更新會覆蓋修改。

turnstile-gate 的做法是在 DSM **前面**驗證：沒通過的請求根本到不了 DSM，不需要修改 DSM。

### 需要 Cloudflare Tunnel 或代理嗎？

不需要。Turnstile 是獨立服務，網站不必經過 Cloudflare。兩者解決不同的問題：

| | 只用 Tunnel | 只用 turnstile-gate |
|---|---|---|
| 不開 port、隱藏 IP、防 DDoS | ✅ | ❌ |
| 擋掉知道網址的 bot | ❌（Tunnel 只轉送，不過濾） | ✅ |

已經在用 Tunnel 的話，Cloudflare 的 WAF Managed Challenge 或 Access 就能達到類似效果，turnstile-gate 的價值在於「不經過 Cloudflare 也能用」或「想完全自訂驗證流程」。若放在 Tunnel 後方，請設 `TRUST_CF_HEADER=1`。

### 會有跨網站（CORS / 第三方 cookie）問題嗎？

不會。Turnstile 元件本來就設計成嵌入任何網站；token 送到同網域；`siteverify` 是伺服器對伺服器；通行 cookie 是第一方 cookie，不受瀏覽器封鎖第三方 cookie 影響。`SameSite=Lax` 讓從其他網站點連結進來可以正常使用，但其他網站的背景請求不會帶上 cookie。

### 閘門算是 CDN 嗎？

不算。它跑在你自己的設備上，對外仍是你家的 IP。它隱藏的是**後端服務**，不是你的 IP；它擋 bot，但不吸收流量。

### 手機 App 怎麼辦？

DS File、Synology Photos 等 App 無法處理驗證頁。選項：

1. `BYPASS_PREFIXES` 放行特定路徑（這些路徑等於沒有保護）
2. **建議**：App 改走 Tailscale / VPN

### `GATE_KEY` 外洩或想讓所有人重新驗證？

換一個新的 `GATE_KEY` 重啟即可，所有既有 cookie 立即失效。
