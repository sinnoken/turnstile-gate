# 部署到 MikroTik RouterOS v7

把 turnstile-gate 跑在路由器的 container 裡，保護內網的 Synology DSM（或任何 Web 服務）。
本文以 RB5009（arm64）為例，設定檔：[`deploy/mikrotik-gate.rsc`](../deploy/mikrotik-gate.rsc)。

```
網際網路 ──443──→ MikroTik（dst-nat）──→ 容器 172.17.0.2:8443 ──HTTPS──→ NAS:5001
                     │                        │
                     └ 防火牆：速率限制          └ 只能連 NAS:5001、外網 443、路由器 DNS
```

## 前置條件

| 項目 | 說明 |
|---|---|
| RouterOS | v7，已安裝 `container` 套件 |
| 硬體架構 | `arm64`（RB5009、hAP ax、CCR2004…）、`arm/v7`、`x86`。**MIPS 機型（hEX、RB750Gr3）不支援 container** |
| 外接儲存 | 建議 USB 碟，放映像、容器根目錄與憑證 |
| 憑證 | 你的網域的 PEM 憑證（`fullchain.pem`、`privkey.pem`）。自動同步見 [cert-sync-dsm.md](cert-sync-dsm.md) |
| Turnstile | Site Key、Secret Key（Hostname 加入你的網域） |

## 步驟

### 1. 開啟 container 功能

```
/system/device-mode/update container=yes
```

依提示在時限內按一下實體 reset 鍵（或冷開機）確認。

### 2. 取得映像

預設由路由器直接從 GHCR 拉 `ghcr.io/sinnoken/turnstile-gate:latest`（多架構，RouterOS 會自動選對的），不用另外下載。
GHCR 套件須設為 **Public**，路由器才能匿名下載。

路由器無法連 GHCR 時，改用 tar：從 [Releases](https://github.com/sinnoken/turnstile-gate/releases) 下載對應架構的 `turnstile-gate-<arch>.tar`，上傳到外接碟根目錄，並把 rsc 的 `/container/add remote-image=$image check-certificate=yes` 改成 `file="$disk/turnstile-gate-arm64.tar"`。也可以自己打包：

```bash
docker buildx build --platform linux/arm64 -o type=docker,dest=turnstile-gate-arm64.tar .
```

### 3. 修改並匯入設定

編輯 `mikrotik-gate.rsc` 開頭的變數：

```
:local nasIP   "192.168.88.10"
:local domain  "nas.example.com"
:local disk    "usb1"
:local image   "ghcr.io/sinnoken/turnstile-gate:latest"
:local siteKey "0x4AAAA..."
:local secret  "0x4AAAA..."
:local gateKey ""
```

`gateKey` 是簽 cookie 用的 `GATE_KEY`。留空時，匯入會用 `:rndstr` 自動產生 64 字元的隨機 hex 金鑰，存在容器環境變數（`/container/envs/print where key=GATE_KEY`）。要自訂就填 `openssl rand -hex 32` 的結果，會照原樣使用。
留空時每次重新匯入都會產生新金鑰，所有人需要重新驗證一次；想保留原本的金鑰，重新匯入前把它填回 `gateKey`。

上傳後匯入：

```
/import mikrotik-gate.rsc
```

設定檔會建立：

| 項目 | 內容 |
|---|---|
| 容器網路 | `br-ct` bridge（172.17.0.1/24）、`veth-gate`（172.17.0.2） |
| NAT | WAN `443` → `172.17.0.2:8443` |
| forward 規則 | 速率限制；容器只能連 `NAS:5001` 與外網 `443` |
| input 規則 | 容器只能查路由器 DNS，其餘一律丟棄 |
| 使用者 | `gatecert`（只限 NAS IP、只給檔案傳輸權限），給 DSM 推送憑證用 |
| container | envs、掛載 `<disk>/gate/cert` → `/cert`、開機自動啟動 |

所有項目的 comment 都含 `gate`，之後可用 `find comment~"gate"` 找到。

> `br-ct` **不要**加入 `LAN` interface list，否則預設防火牆會把容器當成內網信任。

### 4. 放入憑證並啟動

建立 `usb1/gate/cert/`，放入 `fullchain.pem` 與 `privkey.pem`。長期請用 [DSM 自動推送](cert-sync-dsm.md)；第一次測試可以手動從 DSM 匯出：

1. **控制台 → 安全性 → 憑證** → 選網域憑證 → **動作 → 匯出憑證**，解壓縮 zip。
2. 在解壓縮的資料夾執行（WSL 或 Git Bash）：

   ```bash
   { cat ECC-cert.pem; echo; cat ECC-chain.pem; } > fullchain.pem
   cp ECC-privkey.pem privkey.pem
   openssl x509 -in fullchain.pem -noout -subject              # 必須是你的網域
   openssl x509 -in fullchain.pem -noout -pubkey | openssl sha256
   openssl pkey -in privkey.pem -pubout | openssl sha256       # 兩個雜湊必須相同
   ```

   zip 裡沒有 `ECC-*` 檔案（沒開雙憑證）時，改用 `cert.pem`、`chain.pem`、`privkey.pem`。

3. 把 `fullchain.pem`、`privkey.pem` 用 WinBox / WebFig 的 **Files** 上傳到 `usb1/gate/cert/`。

> **容易出錯的地方**
> - **不要用 zip 裡的 `fullchain.pem`**：雙憑證時它只有中繼與根憑證，沒有網域憑證。
> - **中間的 `echo` 不能省**：DSM 的 cert 檔結尾沒有換行，直接 `cat` 會讓 `END`／`BEGIN` 黏在同一行，第一張憑證讀不到。
> - **cert、chain、privkey 要同一組**：`ECC-*` 配 `ECC-*`，`RSA-*`（＝無前綴的 `cert.pem`／`privkey.pem`）配 `RSA-*`，不能混用。

接著：

```
/container/print            # 等 status 變成 stopped（下載與解壓完成）
/container/start [find comment="gate"]
/log/print where topics~"container"
```

看到 `certificate loaded` 與 `HTTPS on :8443` 即成功。

### 5. DSM 端設定

- **控制台 → 安全性 → 受信任的 Proxy**（依 DSM 版本名稱可能不同）加入 `172.17.0.2`，讓 DSM 讀 `X-Real-IP`。
  否則 DSM 眼中所有連線都來自閘門，一旦觸發自動封鎖，**所有人都會被擋**。
- **控制台 → 安全性 → 憑證**：DSM 本身（5001）使用的憑證必須是 `domain` 的有效憑證（例如 Let's Encrypt）。
  閘門以 `nasIP` 連到 DSM，但以 `domain`（`UPSTREAM_SERVER_NAME`）驗證憑證；自簽或其他網域的憑證會讓所有請求都 502。
- 關閉 QuickConnect、路由器與 DSM 的 UPnP，確認 5000/5001 沒有對外。

## 速率限制

程式本身不做速率限制，交給路由器在封包進容器前處理：

```
# 每個來源 IP 同時最多 20 條連線
chain=forward dst-address=172.17.0.2 dst-port=8443 connection-state=new connection-limit=20,32 action=drop
# 每個來源 IP 每分鐘最多 30 條新連線（突發 60）
chain=forward dst-address=172.17.0.2 dst-port=8443 connection-state=new dst-limit=30/1m,60,src-address/10m action=accept
chain=forward dst-address=172.17.0.2 dst-port=8443 connection-state=new action=drop
```

瀏覽器會用 keep-alive 重複使用連線，一般使用不會碰到上限。

## 從家裡連線

NAT 規則只比對 `in-interface-list=WAN`，在家裡用網域連線不會被轉發。家裡請直接用 NAS 內網 IP，或自行加 hairpin NAT。

## 疑難排解

| 症狀 | 可能原因 |
|---|---|
| 匯入時參數錯誤 | 本設定檔依 RouterOS 7.24+ 語法（`list=`、`envlists=`、`mountlists=`、`memory-high=`）；較舊版本的參數名稱不同（`name=`、`envlist=`、`mounts=`、`ram-high=`），依錯誤訊息調整 |
| 拉映像失敗（status 一直是 error 或卡在 downloading） | GHCR 套件不是 Public；路由器本身 DNS 或對外連線有問題；外接碟空間不足 |
| 容器啟動後立刻停止，log 有 `load cert` | 憑證檔不存在或路徑錯誤 |
| log 有 `private key does not match public key` | `fullchain.pem` 第一張不是網域憑證，或 cert 與 key 不同組。用 `openssl x509 -in fullchain.pem -noout -subject` 檢查，依[第 4 步](#4-放入憑證並啟動)重新合併 |
| log 有 `permission denied` | 映像以 UID 65534 執行，掛載檔案權限不足。可在 Dockerfile 移除 `USER 65534` 重新打包 |
| 驗證頁出現但一直失敗，log 有 `siteverify error` | 容器連不到外網：檢查 masquerade 是否涵蓋 `172.17.0.0/24`、DNS 是否可用（`/ip/dns` 的 `allow-remote-requests=yes`） |
| Turnstile 元件顯示錯誤 | Turnstile 後台沒加入此網域 |
| 502 Bad Gateway | `UPSTREAM` 位址錯誤，或 forward 規則沒放行容器到 NAS:5001 |
| 502 Bad Gateway，log 有 `x509` 或 `failed to verify certificate` | DSM 5001 用的不是 `domain` 的有效憑證（自簽、其他網域或已過期），或 `domain` 打錯；路由器時間不正確也會讓憑證驗證失敗，用 `/system/clock/print` 確認並啟用 `/system/ntp/client` |

## 移除

```
/container/stop [find comment="gate"]
/container/remove [find comment="gate"]
/container/envs/remove [find list="gate"]
/container/mounts/remove [find list="gate-cert"]
/ip/firewall/filter/remove [find comment~"gate"]
/ip/firewall/nat/remove [find comment~"gate"]
/user/remove [find name="gatecert"]
/user/group/remove [find name="cert-push"]
/interface/bridge/port/remove [find interface="veth-gate"]
/interface/veth/remove [find name="veth-gate"]
/ip/address/remove [find interface="br-ct"]
/interface/bridge/remove [find name="br-ct"]
```
