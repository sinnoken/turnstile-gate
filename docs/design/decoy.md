# 開發計畫：誘餌登入頁（decoy，選做）

在封鎖機制（[docs/blocking.md](../blocking.md)）上多加一種處理方式：**讓掃描器與撞庫工具打到一個假的登入頁，收集它們送出的帳號，並浪費它們幾秒鐘。**

---

## 1. 目標

| 目標 | 說明 |
|---|---|
| 收集情報 | 對方打哪些路徑、用什麼工具（UA、欄位名稱）、試哪些帳號 |
| 準確認出掃描器 | 打到「真人永遠不會打」的路徑就是掃描器 |
| 浪費對方時間 | 每次 POST 延遲 1～3 秒 |

### 非目標

- **不需要像真的**：一個通用頁面，閘門自己的風格，不模仿 Synology、WordPress 等任何產品（撞庫工具對已知路徑盲打，不檢查頁面長相；被認出是蜜罐也無所謂）。
- **不是 tarpit**：連線在回應後就結束。
- **不反擊**：不送 zip bomb、惡意內容，不主動連回對方。

### 原則

- 沿用 [plan.md](plan.md) §2.1。
- 約 60 行，在閘門內實作（不另開服務與防火牆規則），維持單一 `main.go`、只用標準函式庫。
- **寧可漏封也不誤封**：任何真人可能觸發的路徑都不能當誘餌。
- 參數與清單寫死在常數。

## 2. 不做的事

| 做法 | 理由 |
|---|---|
| 記錄只做 SYN 掃描的 IP | 半開連線在核心就結束，`Accept()` 看不到；SYN 來源可偽造，會灌爆封鎖表並誤封真人 |
| 路由器 `psd`（port scan detection） | 慢速掃描繞得過、NAT 後多人易誤判，來源同樣可偽造 |
| tarpit（拖住連線） | 消耗的是 RB5009 自己的 goroutine、socket、conntrack；現代掃描器逾時很短不受影響。真要做用 RouterOS `action=tarpit` |
| 模仿真實產品的多個樣板 | 要維護多份樣板與失敗回應格式，還有商標與著作權問題，情報量差不多 |
| 偽造指紋（假 `Server` 標頭、仿其他產品的錯誤頁） | 與「不需要像真的」相反；Go 預設不送 `Server` 標頭 |
| `/.env`、`/.git/config` 回假檔案內容 | 所有誘餌路徑回同一個登入頁較精簡；日誌證明這類路徑常被打時再評估（§6） |

## 3. 設計

### 3.1 請求流程與判斷順序

```
TLS 握手
  │ SNI 不在 ALLOWED_HOSTS ──→ 中斷握手（嚴格 SNI）
  ▼
請求
  │
  ▼
Host 檢查（ALLOWED_HOSTS）── 不符 ──→ 421（不算事件）
  │
  ▼
有效 cookie？ ── 是 ──→ 轉發上游          ← 必須在誘餌判斷之前
  │否
  ▼
誘餌路徑？或 IP 在 decoy 狀態？
  ├─ 否 ──→ 一般流程（BYPASS_PREFIXES／驗證頁／401）
  └─ 是 ──→ 誘餌名額還有？
              ├─ 否 ──→ Close()（等同封鎖）
              └─ 是 ──→ GET  → 登入頁
                        POST → 記錄 → 延遲 1～3 秒 → 登入頁＋「帳號或密碼錯誤」
                        並把 IP 標記為 decoy（私有 IP 除外）
```

- **有效 cookie 一定先放行**：否則已登入使用者打到某條路徑時會被誤導進誘餌。
- 只用 IP 盲掃的掃描器在 TLS 層就被嚴格 SNI 擋掉；誘餌只處理**已經知道網域**的掃描器（網域在 Certificate Transparency 日誌公開）。

### 3.2 誘餌路徑

只挑**這個部署沒有在用的技術**，用前綴比對。

| ✅ 可以 | ❌ 不可以 |
|---|---|
| PHP、WordPress、phpMyAdmin、`.env`、`.git`、Spring Actuator、各家 IoT 路由器路徑 | 上游真的會服務的路徑（DSM：`/webapi/`、`/webman/`、`/scripts/` 等） |
| | 與 `BYPASS_PREFIXES` 重疊的路徑 |
| | `/`、`/login`、`/admin` 這類太泛、真人可能打的路徑 |

> **反例**：`/webapi/entry.cgi` 是撞庫工具常打的 Synology 端點，但 DSM 網頁介面登入後也一直在呼叫它；cookie 過期時，已開著的 DSM 頁面會帶著過期 cookie 打它，家人的 IP 就會被標記。

**起始清單（約 30～50 條，實作時對照參考來源補齊）：**

```
/wp-  /xmlrpc.php  /.env  /.git/  /phpmyadmin  /pma/  /vendor/phpunit
/actuator  /cgi-bin/  /boaform/  /HNAP1  /owa/  /solr/  /.aws/  /config.json
```

| 參考來源 | 用途 |
|---|---|
| SecLists（`danielmiessler/SecLists`，MIT）`Discovery/Web-Content/`，例如 `quickhits.txt`、`CMS/` | 起始清單 |
| nuclei-templates（ProjectDiscovery） | 目前流行的攻擊目標 |
| GreyNoise、蜜罐公開報告 | 全網實際觀察到的掃描路徑 |
| **自己的日誌** | **最準**；上線後依此修正（§5） |

清單寫死在程式碼。更新方式：改程式 → 重建映像 → `repull`。

### 3.3 登入頁

- 一個 `html/template`：帳號欄、密碼欄、按鈕。沿用驗證頁的 CSS（淺色／深色）。
- 標題只寫「Sign in」，**不出現任何產品名稱或商標**。
- POST 後回同一頁，加上「帳號或密碼錯誤」。不論送什麼都失敗，HTTP `200`。

### 3.4 POST 處理

| 項目 | 設計 |
|---|---|
| body 上限 | `http.MaxBytesReader` 4 KB，超過回 `413` |
| 格式 | 接受 `application/x-www-form-urlencoded` 與 JSON；其他只記錄大小 |
| 帳號欄位 | 依序找 `user`、`username`、`log`、`account`、`email`、`login`，找到第一個就用 |
| 密碼欄位 | 依序找 `pass`、`password`、`pwd`、`passwd` |
| 延遲 | `time.Sleep(1s + rand(0..2s))`，持有名額期間計入 |

### 3.5 記錄

```json
{"level":"INFO","msg":"decoy","ip":"203.0.113.50","method":"POST","path":"/wp-login.php",
 "ua":"python-requests/2.31","fields":["log","pwd","wp-submit"],
 "user":"admin","pass_sha256":"5e88…","pass_len":8,"body_bytes":96}
```

| 欄位 | 說明 |
|---|---|
| `user` | 原樣記錄（截斷 64 字元） |
| `pass_sha256`、`pass_len` | **只存雜湊與長度，永不存明文**（撞庫帳密常是真實外洩資料；雜湊仍可統計同一密碼被試幾次） |
| `fields` | 表單欄位名稱，用來辨識工具 |
| GET 也記錄 | 不含 `user`／`pass_*` |

- 由 slog JSON handler 輸出（自動跳脫）；另外濾掉控制字元，避免看日誌的終端機被惡意字元影響。
- 經 RouterOS `/log`（`logging=yes`）出去；需要集中保存時由路由器轉 syslog（`/system/logging/action` `target=remote`），閘門不需要知道 syslog。

### 3.6 資源上限

| 資源 | 上限 | 超過時 |
|---|---|---|
| 同時處理的誘餌請求 | 64（`chan struct{}` 當 semaphore） | `Close()` |
| 單一請求存活時間 | 延遲 ≤ 3 秒 + 寫出，另設 `http.TimeoutHandler` 10 秒 | 中斷 |
| 回應大小 | 頁面約 2 KB | — |
| 每 IP 同時連線 | 路由器速率限制（[deploy-mikrotik.md](../deploy-mikrotik.md#速率限制)） | 防火牆處理 |

估算：64 × 數 KB ＋ goroutine ≈ 1～2 MB，在 `GOMEMLIMIT=48MiB` 內。最壞情況等同封鎖（名額滿就 `Close()`）。

### 3.7 與封鎖機制的整合

| 封鎖機制（[docs/blocking.md](../blocking.md)） | 變更 |
|---|---|
| [「什麼會被封鎖」](../blocking.md#什麼會被封鎖)的事件 | 新增 `decoy_hit`：打到誘餌路徑（與 `bad_cookie`、`verify_fail` 並列） |
| 封鎖表 `offender` | 新增 `decoy` 到期時間（與 `until` 並列）。進入 decoy 的 IP 之後打任何路徑都只看到登入頁 |
| decoy 時效 | 24 小時，不累犯加重（目的是收集情報，不是懲罰） |
| [「封鎖時長」](../blocking.md#封鎖時長)的私有 IP 規則 | 一樣永不標記；私有 IP 打到誘餌路徑只回 `404`，不進誘餌 |
| listener 層封鎖（[「兩層封鎖」](../blocking.md#兩層封鎖) A） | 不變。被**封鎖**的 IP 仍在 listener 層 `Close()`；只有 **decoy** 狀態的 IP 會進到 handler |

## 4. 風險

| 風險 | 處理 |
|---|---|
| **真人被誤導，輸入真正的 DSM 密碼** | 最嚴重。① 密碼只存雜湊 ② 有效 cookie 先放行 ③ 誘餌路徑排除上游會用的路徑 ④ 私有 IP 不進誘餌 |
| 撞庫用的帳密常是**真實外洩資料** | 只存雜湊，日誌外洩也不會變成二次外洩 |
| 攻擊者控制的字串進日誌 | JSON 跳脫＋濾控制字元；`user` 截斷 |
| 誘餌被灌爆 | 名額 64、body 4 KB、逾時 10 秒，滿了退回 `Close()` |
| CGNAT 後的真人被一起標記 | 只有打誘餌路徑才標記，真人不會打；decoy 時效 24 小時 |

## 5. 實作計畫

| 順序 | 項目 | 驗收條件 |
|:-:|---|---|
| 1 | 誘餌路徑清單與前綴比對 | 清單中沒有任何 DSM 路徑；`/wp-login.php`、`/.env` 命中，`/webapi/entry.cgi`、`/` 不命中 |
| 2 | 判斷順序 | 帶有效 cookie 打誘餌路徑 → 轉發上游；不帶 cookie → 誘餌頁 |
| 3 | 登入頁與 POST 處理 | 任意 POST 都回「帳號或密碼錯誤」、延遲 1～3 秒；5 KB body 回 `413` |
| 4 | 記錄 | 日誌有 `user`、`pass_sha256`、`pass_len`，**沒有明文密碼**；控制字元被濾掉 |
| 5 | 名額上限 | 第 65 個同時請求被 `Close()` |
| 6 | 狀態機整合 | 打誘餌後該 IP 打任何路徑都看到登入頁；24 小時後恢復；私有 IP 打誘餌只回 `404` |
| 7 | `gate_test.go` | 涵蓋 1～6（`now` 可注入，延遲可在測試中設為 0） |
| 8 | 文件 | `docs/blocking.md` 加一節誘餌說明；README 特色一行 |

**上線後修正清單：** 以 `LOG_LEVEL=debug` 跑一到兩週，統計「沒有 cookie、非正常流程」的請求路徑，把常見的補進清單、把從未出現的移除。info 等級不記錄這類請求（[docs/blocking.md「日誌」](../blocking.md#日誌)）。

### 每次更新誘餌清單的檢查

- [ ] 沒有任何一條是 `UPSTREAM` 實際會服務的路徑
- [ ] 與 `BYPASS_PREFIXES` 沒有重疊
- [ ] 判斷順序仍為：Host 檢查 → 有效 cookie → 誘餌 → 一般流程
- [ ] 沒有 `/`、`/login`、`/admin` 這類太泛的路徑

## 6. 日後要重新檢視的地方

- **誘餌名額常常是滿的**：先確認路由器端封鎖（[docs/blocking.md「兩層封鎖」](../blocking.md#兩層封鎖) B）有在運作，而不是調大名額。
- **出現真人被導到誘餌頁的回報**：立即檢查清單是否誤含上游路徑，並縮短 decoy 時效。
- **日誌顯示大量 POST 集中在某些端點**：可針對那些端點回更接近原產品的失敗格式，讓工具多試幾次——先確認情報價值值得這份維護成本。
- **`/.env`、`/.git/config` 常被打**：評估回假檔案內容。
- **多網域／多後端（`ROUTES`）實作後**：誘餌清單要排除**所有**後端會用到的路徑，不只 DSM。
