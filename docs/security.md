# 安全模型與 FAQ

## turnstile-gate 擋什麼、不擋什麼

| 威脅 | 結果 | 說明 |
|---|:-:|---|
| 大量掃描、撞庫、暴力破解的 bot | ✅ | 主要用途 |
| 用 IP 盲掃的掃描器 | ✅ | 設 `ALLOWED_HOSTS` 後 TLS 握手直接中斷（嚴格 SNI），拿不到憑證與網域；不入封鎖表 |
| 偽造 cookie、偽造或重複送 token 的 bot | ✅ | 自動封鎖該 IP：1 小時起，7 天內累犯 24 小時、7 天；可交給路由器在最外層丟棄。見 [封鎖機制](blocking.md) |
| 慢速、每次都換 IP 的掃描 | ⚠️ | 只要沒做出上面那些事就不會被封（寧可漏封，不要誤封）；交給驗證頁與路由器速率限制 |
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
| 閘門自動封鎖 + 路由器丟棄（`gate-block`） | 確定是 bot 的 IP 再次嘗試 | 建議 |
| 容器網路隔離 | 閘門本身被攻破 | 建議（尤其跑在路由器上） |
| Cloudflare 代理 / Tunnel | DDoS、隱藏 IP | 選用 |
| 不對外，改用 Tailscale / VPN | 幾乎全部 | 只有自己人使用時最佳 |

## 設計上的安全細節

- **一定在伺服器端驗證**：token 交給 `siteverify` 驗證，並比對回傳的 `hostname`，別的網站產生的 token 不能用。
- **cookie 防偽造**：`<到期時間>.<HMAC-SHA256>`，以 `GATE_KEY` 簽章、constant-time 比對。
- **cookie 屬性**：`HttpOnly`、`Secure`、`SameSite=Lax`；不轉送給後端。
- **防 open redirect**：`next` 只接受站內相對路徑。含控制字元（TAB、換行等）的一律拒絕；先照 `http.Redirect` 的方式整理路徑（`/./\evil.com` → `/\evil.com`）再檢查一次，`//`、`/\` 開頭的都改成 `/`。
- **只認自己的網域**：設 `ALLOWED_HOSTS` 後，HTTPS 模式下 SNI 不在清單（直接打 IP 的掃描器）就中斷 TLS 握手、不送出憑證（嚴格 SNI，同 nginx 的 `ssl_reject_handshake on`）；`Host` 不在清單的請求回 `421`，看不到驗證頁，也碰不到後端。兩者都不算封鎖事件。限制：TCP 交握仍會成功；網域本來就公開在 Certificate Transparency 日誌。
- **自動封鎖**：只有真人不會做的事才算事件——所有 `__gate` cookie 都格式錯誤（`bad_cookie`）、送出空的、偽造的、他站的 token（`verify_fail` 強訊號，立即封）、10 分鐘內兩次 `timeout-or-duplicate`（弱訊號）。私有 IP 永不封鎖；封鎖表只在記憶體，上限 50,000 筆，表滿時淘汰沒在封鎖的舊紀錄。被封鎖的 IP 在 TLS 握手前就被關閉連線。細節見 [blocking.md](blocking.md)。
- **路由器整合不給帳密**：路由器每分鐘拉閘門的 `/blocklist.json`（只在內部位址監聽），寫進有時效的 address-list；容器拿不到任何 RouterOS 帳密，清單拉不到時項目自然到期，不會留下永久封鎖。
- **免驗證路徑**：`BYPASS_PREFIXES` 只在解碼後的路徑沒有 `..` 片段時放行，`/webdav/%2e%2e/webapi/...` 這類編碼過的跳脫會被要求驗證。
- **後端憑證**：設 `UPSTREAM_SERVER_NAME` 時以該網域驗證後端憑證，內網有人冒充後端 IP 時連線會失敗（502），不會把帳密送給對方。`UPSTREAM_INSECURE=1` 完全不驗證，只在後端是自簽憑證、且接受這個風險時使用。
- **IP 來源**：預設使用 TCP 連線位址。`CF-Connecting-IP` 只在 `TRUST_CF_HEADER=1` 時採用，避免直接對外時被偽造（否則攻擊者能把別人的 IP 送進封鎖表，或躲開封鎖）。
- **日誌**：JSON 格式，欄位自動跳脫，使用者字串無法偽造出另一行；不記錄 cookie 值與 token。
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

換一個新的 `GATE_KEY` 重啟即可，所有既有 cookie 立即失效。舊 cookie 會被判為「簽章不符」：閘門清除它、讓使用者重新驗證一次，**不算封鎖事件，不會封鎖任何人**。

`GATE_KEY` 必須是只有你知道的隨機值，不要沿用範例或文件裡的字串。MikroTik 設定檔的 `gateKey` 留空時會自動產生；要更換時：

```
/container/stop [find comment="gate"]
/container/envs/set [find list="gate" key="GATE_KEY"] value=[:rndstr length=64 from="0123456789abcdef"]
/container/start [find comment="gate"]
```
