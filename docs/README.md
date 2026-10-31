# 文件索引

每一類規格只寫在一份文件裡；其他文件用一句話帶過並連結過來，不重複數字與細節。

| 文件 | 唯一負責的內容 | 對象 | 規則 |
|---|---|---|---|
| [`README.md`](../README.md)（根目錄） | 簡介與使用手冊：是什麼、運作原理、快速開始、端點、限制；**環境變數**（「設定」表） | 使用者 | 環境變數只在「設定」表說明，其他文件與範例設定檔只放範例值並連結過來；表格要與 `main.go` 一致 |
| [`blocking.md`](blocking.md) | 封鎖機制的現行行為：事件、時長、累犯視窗、封鎖表上限與淘汰、封鎖清單 JSON、日誌等級與訊息、查詢與解除封鎖 | 使用者、維運 | 封鎖相關的數字與規則只寫在這裡；其他文件連結到對應章節 |
| [`security.md`](security.md) | 安全模型與取捨：擋什麼、不擋什麼、建議防護組合、設計上的安全細節、FAQ | 使用者 | 只寫取捨與理由；行為細節連結到 `blocking.md`，操作步驟連結到部署文件 |
| [`deploy-mikrotik.md`](deploy-mikrotik.md) | MikroTik RouterOS 部署與維運步驟：匯入、憑證放置、速率限制、封鎖清單路由器端、更新與退回映像、更換 `GATE_KEY`、疑難排解、移除 | 維運 | RouterOS 指令只寫在這裡（對應 `deploy/mikrotik-gate.rsc`）；不重述閘門行為與變數語意 |
| [`cert-sync-dsm.md`](cert-sync-dsm.md) | 從 Synology DSM 自動推送憑證（`deploy/dsm-push-cert.sh`） | 維運 | 憑證合併與推送流程只寫在這裡 |
| [`development.md`](development.md) | 開發與測試：指令、換行規則、CI、Go 版本、驗證頁字型 | 開發 | 開發流程只寫在這裡；使用者自行建置留在 README「建置」 |
| [`design/plan.md`](design/plan.md) | 開發計畫：尚未完成的工作與驗收條件 | 開發 | 只寫計畫，不寫現行行為；完成的項目寫進對應的規格文件後從計畫移除 |
| [`design/decoy.md`](design/decoy.md) | 誘餌登入頁（選做）的設計 | 開發 | 只寫誘餌本身的設計；引用封鎖機制時連結 `blocking.md` 章節 |
| [`images/`](images/) | 驗證頁截圖（`gate-light.png`、`gate-dark.png`，用於 README） | — | 驗證頁外觀改變時重新截圖 |

範例設定檔 [`deploy/docker-compose.yml`](../deploy/docker-compose.yml)、[`deploy/mikrotik-gate.rsc`](../deploy/mikrotik-gate.rsc) 只放範例值，變數說明連結 README「設定」。

## 維護規則

- 新增文件時，同一個 commit 把它加進本索引。
- 行為改變時，同一個 commit 更新負責該規格的文件（上表「唯一負責的內容」）。
- 其他文件只連結，不複製；需要提到時用一句話摘要加連結到對應章節。
- 改章節標題時，一併更新指向它的連結（GitHub 錨點由標題產生）。
