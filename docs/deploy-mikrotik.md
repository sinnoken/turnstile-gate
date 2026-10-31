# 部署到 MikroTik RouterOS v7

把 turnstile-gate 跑在路由器的 container 裡，保護內網的 Synology DSM（或任何 Web 服務）。
本文以 RB5009（arm64）為例，設定檔：[`deploy/mikrotik-gate.rsc`](../deploy/mikrotik-gate.rsc)。

```
網際網路 ──443──→ MikroTik（raw 丟棄、dst-nat）──→ 容器 172.17.0.2／fd17::2:8443 ──HTTPS──→ NAS:5001
                     │      ▲                        │
                     │      └── 每分鐘拉封鎖清單 ──── :9090
                     └ 防火牆：速率限制                └ 只能連 NAS:5001、外網 443、路由器 DNS
```

## 前置條件

| 項目 | 說明 |
|---|---|
| RouterOS | v7，已安裝 `container` 套件 |
| 硬體架構 | `arm64`（RB5009、hAP ax、CCR2004…）、`arm/v7`、`x86`。**MIPS 機型（hEX、RB750Gr3）不支援 container** |
| 外接儲存 | 建議 USB 碟，放映像、容器根目錄與憑證 |
| 憑證 | 你的網域的 PEM 憑證（`fullchain.pem`、`privkey.pem`）。自動同步見 [cert-sync-dsm.md](cert-sync-dsm.md) |
| Turnstile | Site Key、Secret Key（Hostname 加入你的網域） |
| IPv6 防火牆 | `/ipv6/firewall/filter` 要有 forward 與 input 規則（出廠預設防火牆即可），設定檔會插在最上面；沒有規則時匯入會直接停下、不做任何修改。WAN 沒有 IPv6 也照樣匯入，見 [IPv6](#ipv6) |

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

`domain` 是使用者連線用的網域，會填進 `UPSTREAM_SERVER_NAME` 與 `ALLOWED_HOSTS`；`siteKey`、`secret`、`gateKey` 分別填進 `TURNSTILE_SITEKEY`、`TURNSTILE_SECRET`、`GATE_KEY`。各變數的作用見 [README 設定](../README.md#設定)。

`gateKey` 留空時，匯入會用 `:rndstr` 自動產生 64 字元的隨機 hex 金鑰，存在容器環境變數（`/container/envs/print where key=GATE_KEY`）。要自訂就填 `openssl rand -hex 32` 的結果，會照原樣使用。
留空時每次重新匯入都會產生新金鑰，所有人需要重新驗證一次；想保留原本的金鑰，重新匯入前把它填回 `gateKey`。

上傳後匯入：

```
/import mikrotik-gate.rsc
```

設定檔會建立：

| 項目 | 內容 |
|---|---|
| 容器網路 | `br-ct` bridge（`172.17.0.1/24`、`fd17::1/64`）、`veth-gate`（`172.17.0.2`、`fd17::2`） |
| NAT | WAN `443` → `172.17.0.2:8443`；IPv6 WAN `443` → `[fd17::2]:8443`，容器的 IPv6 出站 masquerade |
| forward 規則 | 速率限制；容器只能連 `NAS:5001` 與外網 `443`（IPv6 只開外網 `443`）；IPv6 從 WAN 進來的新連線只放行轉給閘門的 |
| input 規則 | 容器只能查路由器 DNS（IPv4），其餘一律丟棄 |
| 使用者 | `gatecert`（只限 NAS IP、只給檔案傳輸權限），給 DSM 推送憑證用 |
| container | envs（含 `BLOCKLIST_LISTEN=172.17.0.2:9090`）、掛載 `<disk>/gate/cert` → `/cert`、開機自動啟動 |
| 封鎖清單 | script `gate-blocklist`、每分鐘執行的 scheduler `gate-blocklist`、`/ip` 與 `/ipv6` 的 raw 規則（丟棄 address-list `gate-block`）；forward 擋其他主機連 9090、input 放行清單的回應。見[封鎖清單](#封鎖清單路由器端) |

所有項目的 comment 都含 `gate`（script 沒有 comment，以名稱 `gate-blocklist` 辨識），之後可用 `find comment~"gate"` 找到。

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

看到 `"msg":"certificate loaded"` 與 `"msg":"start","mode":"https"` 即成功（日誌為 JSON，見 [blocking.md](blocking.md#日誌)）。

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

IPv6 有同樣三條（`dst-address=fd17::2`）。連線數上限以 `/64` 計（`connection-limit=20,64`），與閘門的封鎖單位一致；`dst-limit` 沒有前綴長度可設，新連線速率仍以單一位址計。

瀏覽器會用 keep-alive 重複使用連線，一般使用不會碰到上限。

## IPv6

IPv6 比照 IPv4：容器只有內部的 ULA 位址 `fd17::2`，路由器把 WAN 的 IPv6 443 以 dst-nat 轉給閘門，容器出站以 masquerade（NAT66）用路由器的位址出去。閘門看到的來源是用戶端的真實 IPv6，封鎖以 `/64` 為單位（見 [blocking.md](blocking.md#封鎖時長)）。閘門連 DSM 仍走 IPv4（`UPSTREAM`），DSM 本身不對外開放 IPv6。

- **DNS**：網域的 AAAA 指向**路由器 WAN 的 IPv6 位址**（`/ipv6/address/print where interface=<WAN 介面>` 的全域位址）。ISP 的前綴會變動時，用能更新路由器位址的 DDNS。
- **Synology DDNS 不要更新 AAAA**：AAAA 指向 NAS 的話，IPv6 用戶端會直接連 NAS、繞過閘門。在 DSM 的 DDNS 設定關掉 IPv6 位址的更新，或確認 AAAA 不是 NAS 的位址。
- **外網直連 NAS 由路由器的 IPv6 防火牆負責擋**：設定檔不另外加規則。出廠預設的 IPv6 防火牆（forward 最後一條 `drop everything else not coming from LAN`）已經會擋；改過預設防火牆的話，自行確認 WAN 進來的新連線只放行轉給閘門的部分。
- **dst-nat 只比對路由器自己的位址**（`dst-address-type=local`）：IPv6 沒有 NAT，往內網主機全域位址的 443 不會被攔截。
- **br-ct 不發 RA**（`advertise=no`）：容器只有固定的 `fd17::2`，防火牆規則才比對得到。
- **WAN 沒有 IPv6**：規則照樣建立，只是用不到；之後 ISP 開通 IPv6 時只要設好 AAAA。

確認（從外部 IPv6 網路，例如手機行動網路）：

```
curl -6 -sI https://<網域>/__gate                              # 回 200
/ipv6/firewall/nat/print stats where comment~"gate"            # dst-nat 的 packets 增加
/log/print where topics~"container" message~"\"msg\":\"event\""   # 觸發事件時 ip 是用戶端的 IPv6
```

### 已部署的路由器加上 IPv6

用舊版設定檔部署的路由器：先停容器，加上 IPv6 位址、更新映像：

```
/container/stop [find comment="gate"]
/ipv6/address/add address=fd17::1/64 interface=br-ct advertise=no comment="gate"
/interface/veth/set [find name="veth-gate"] address=172.17.0.2/24,fd17::2/64 gateway6=fd17::1
/container/repull [find comment="gate"]
/container/print                      # 等 status 回到 stopped
/container/start [find comment="gate"]
```

再貼上以下內容（要整段一起貼，`{ }` 內的 `:local` 才有效）：

```
{
/ipv6/firewall/nat/add chain=dstnat in-interface-list=WAN dst-address-type=local \
    protocol=tcp dst-port=443 action=dst-nat to-address=fd17::2 to-ports=8443 \
    comment="gate: WAN443->gate"
/ipv6/firewall/nat/add chain=srcnat src-address=fd17::/64 out-interface-list=WAN \
    action=masquerade comment="gate: container masquerade"
:local f6Top [:pick [/ipv6/firewall/filter/find chain=forward dynamic=no] 0]
/ipv6/firewall/filter/add place-before=$f6Top chain=forward action=drop \
    dst-address=fd17::2 protocol=tcp dst-port=8443 connection-state=new \
    connection-limit=20,64 comment="gate: per-/64 max 20 conns"
/ipv6/firewall/filter/add place-before=$f6Top chain=forward action=accept \
    dst-address=fd17::2 protocol=tcp dst-port=8443 connection-state=new \
    dst-limit=30/1m,60,src-address/10m comment="gate: per-IP 30 new conn/min"
/ipv6/firewall/filter/add place-before=$f6Top chain=forward action=drop \
    dst-address=fd17::2 protocol=tcp dst-port=8443 connection-state=new \
    comment="gate: over rate limit"
/ipv6/firewall/filter/add place-before=$f6Top chain=forward action=accept \
    src-address=fd17::2 out-interface-list=WAN protocol=tcp dst-port=443 \
    comment="gate: container -> internet 443 (siteverify)"
/ipv6/firewall/filter/add place-before=$f6Top chain=forward action=drop \
    src-address=fd17::/64 connection-state=new \
    comment="gate: container isolation"
:local i6Top [:pick [/ipv6/firewall/filter/find chain=input dynamic=no] 0]
/ipv6/firewall/filter/add place-before=$i6Top chain=input action=drop \
    src-address=fd17::/64 comment="gate: no router access"
/ipv6/firewall/raw/add chain=prerouting in-interface-list=WAN src-address-list=gate-block \
    action=drop comment="gate: blocklist"
}
```

最後換掉 `gate-blocklist` script，讓 IPv6 的 `/64` 寫進 `/ipv6/firewall/address-list`：

```
/system/script/remove [find name="gate-blocklist"]
```

再貼上[已部署的路由器加上封鎖清單](#已部署的路由器加上封鎖清單)裡的 `/system/script/add name=gate-blocklist source={ ... }` 那一段（scheduler 以名稱呼叫，不用重建）。用 `/system/script/run gate-blocklist` 確認沒有 warning，再照上面的「確認」測試。

## 封鎖清單（路由器端）

閘門判斷要封鎖的 IP（事件與時長見 [blocking.md](blocking.md)），路由器只照清單在最外層丟棄：不進 conntrack、不經 NAT、不到容器，也撐過容器重啟與 `repull`。

`mikrotik-gate.rsc` 會加入：

| 項目 | 內容 |
|---|---|
| env | `BLOCKLIST_LISTEN=172.17.0.2:9090`（見 [README 設定](../README.md#設定)），只在容器網段監聽。WAN 只轉 443，9090 從網際網路連不到 |
| script `gate-blocklist` | 用 `/tool/fetch` 拉清單、`:deserialize` 解析 JSON，把每個 IP 寫進 address-list `gate-block`（`ip` 含 `:` 的 IPv6 `/64` 寫進 `/ipv6/firewall/address-list`，其他寫進 `/ip/firewall/address-list`），`timeout` = 剩餘秒數，comment = `gate: <事件> #<次數>`；已存在就更新 timeout |
| scheduler `gate-blocklist` | 每 1 分鐘執行一次 |
| raw 規則 `gate: blocklist` | `/ip/firewall/raw` 與 `/ipv6/firewall/raw` 各一條：`chain=prerouting in-interface-list=WAN src-address-list=gate-block action=drop` |
| forward 規則 `gate: blocklist router only` | 擋區網其他主機連 `172.17.0.2:9090`（路由器自己拉取走 output，不受影響）。不需要時可刪 |
| input 規則 `gate: blocklist replies` | 放行容器回給路由器的封包（`gate: no router access` 會擋掉所有來自容器網段的 input） |

- 拉取或解析失敗：該輪只記一行 `gate-blocklist: ...` warning，既有項目照 timeout 到期，下一分鐘再試。容器停止期間每分鐘會有一行，維護時間較長可先 `/system/scheduler/disable gate-blocklist`。
- 路由器重開機：有 timeout 的 address-list 項目是動態的，會消失；閘門封鎖表仍在，下一輪補回。
- 清單大小：閘門端已限制筆數，讓 `/tool/fetch` 讀得完，路由器端不需調整；上限與原因見 [封鎖清單 JSON](blocking.md#封鎖清單-json)。
- raw 規則是加在 prerouting 的最後面；如果你原本有 `action=accept` 的 raw 規則會先比對到，請把 `gate: blocklist` 移到最上面（`/ip` 與 `/ipv6` 各自檢查）。
- device-mode 為 `home` 時不能使用 scheduler（RouterOS 手冊 Scheduler 指南），用 `/system/device-mode/print` 確認。

查詢與解除封鎖見 [blocking.md](blocking.md#查詢誰被封鎖)。

### 已部署的路由器加上封鎖清單

用舊版設定檔部署的路由器，先補 env 並更新映像：

```
/container/stop [find comment="gate"]
/container/envs/add list=gate key=BLOCKLIST_LISTEN value="172.17.0.2:9090"
/container/repull [find comment="gate"]
/container/print                      # 等 status 回到 stopped
/container/start [find comment="gate"]
```

再貼上以下內容（直接貼到終端機，或存成 `.rsc` 後 `/import`）：

```
/ip/firewall/filter/add place-before=[find comment="gate: no router access"] chain=input     action=accept src-address=172.17.0.2 protocol=tcp src-port=9090     connection-state=established,related comment="gate: blocklist replies"
/ip/firewall/filter/add place-before=[find comment="gate: container isolation"] chain=forward     action=drop dst-address=172.17.0.2 protocol=tcp dst-port=9090     comment="gate: blocklist router only"
/system/script/add name=gate-blocklist source={
    :onerror e in={
        :local r [/tool/fetch url="http://172.17.0.2:9090/blocklist.json" output=user as-value]
        :local j [:deserialize from=json value=($r->"data")]
        :foreach it in=($j->"items") do={
            :local ip ($it->"ip")
            :local t [:totime (($it->"ttl") . "s")]
            :local c ("gate: " . ($it->"event") . " #" . ($it->"strike"))
            :if ([:tostr $ip] ~ ":") do={
                :local id [/ipv6/firewall/address-list/find list=gate-block address=$ip]
                :if ([:len $id] = 0) do={
                    /ipv6/firewall/address-list/add list=gate-block address=$ip timeout=$t comment=$c
                } else={
                    /ipv6/firewall/address-list/set $id timeout=$t comment=$c
                }
            } else={
                :local id [/ip/firewall/address-list/find list=gate-block address=$ip]
                :if ([:len $id] = 0) do={
                    /ip/firewall/address-list/add list=gate-block address=$ip timeout=$t comment=$c
                } else={
                    /ip/firewall/address-list/set $id timeout=$t comment=$c
                }
            }
        }
    } do={ :log warning "gate-blocklist: $e" }
}
/system/scheduler/add name=gate-blocklist interval=1m on-event=gate-blocklist comment="gate"
/ip/firewall/raw/add chain=prerouting in-interface-list=WAN src-address-list=gate-block     action=drop comment="gate: blocklist"
```

IPv6 的 raw 規則與其他 IPv6 設定見[已部署的路由器加上 IPv6](#已部署的路由器加上-ipv6)。

確認：

```
/system/script/run gate-blocklist
/log/print where message~"gate-blocklist"             # 沒有 warning 即正常
/ip/firewall/address-list/print where list=gate-block  # 有人被封鎖時才會有項目
/ipv6/firewall/address-list/print where list=gate-block
/ip/firewall/raw/print stats where comment~"gate"      # packets 計數會增加
/ipv6/firewall/raw/print stats where comment~"gate"
```

## 從家裡連線

NAT 規則（IPv4、IPv6）只比對 `in-interface-list=WAN`，在家裡用網域連線不會被轉發。家裡請直接用 NAS 內網 IP，或自行加 hairpin NAT。

## 更新映像

`remote-image` 只在建立容器時拉一次，之後不會自動更新。`main` 有新版的 `:latest` 時：

```
/container/stop [find comment="gate"]
/container/repull [find comment="gate"]
/container/print                      # 等 status 回到 stopped（下載與解壓完成）
/container/start [find comment="gate"]
```

envs、掛載、網路與開機自動啟動都會保留，只換映像。新版需要新的 env 時，在 `stop` 之後、`start` 之前調整 `/container/envs`（封鎖清單見[上一節](#已部署的路由器加上封鎖清單)），例如用舊版設定檔部署的路由器要補上：

```
/container/envs/remove [find list="gate" key="UPSTREAM_INSECURE"]
/container/envs/add list=gate key=UPSTREAM_SERVER_NAME value="你的網域"
/container/envs/add list=gate key=ALLOWED_HOSTS        value="你的網域"
```

`CERT_FILE`、`KEY_FILE`、`SESSION_HOURS`、`GOMEMLIMIT` 若與 [README 設定](../README.md#設定) 的預設值相同，可以刪掉不設。

更新後確認：`/log/print where topics~"container"` 有 `"msg":"start"`，從外網開一次驗證頁並登入 DSM。

### 退回舊版

每個 [Release](https://github.com/sinnoken/turnstile-gate/releases) 的映像都有版本 tag（例如 `:1.0.0`）。新版有問題時，指定上一版重新拉取：

```
/container/stop [find comment="gate"]
/container/repull [find comment="gate"] remote-image="ghcr.io/sinnoken/turnstile-gate:1.0.0"
/container/print                      # 等 status 回到 stopped
/container/start [find comment="gate"]
```

修正版發布後，用同樣方式指定 `:latest` 換回來。

## 更換 GATE_KEY

`GATE_KEY` 外洩或想讓所有人重新驗證時（影響見 [安全模型 FAQ](security.md#gate_key-外洩或想讓所有人重新驗證)），換一把新的隨機金鑰：

```
/container/stop [find comment="gate"]
/container/envs/set [find list="gate" key="GATE_KEY"] value=[:rndstr length=64 from="0123456789abcdef"]
/container/start [find comment="gate"]
```

## 疑難排解

| 症狀 | 可能原因 |
|---|---|
| 匯入時參數錯誤 | 本設定檔依 RouterOS 7.24+ 語法（`list=`、`envlists=`、`mountlists=`、`memory-high=`）；較舊版本的參數名稱不同（`name=`、`envlist=`、`mounts=`、`ram-high=`），依錯誤訊息調整 |
| 拉映像失敗（status 一直是 error 或卡在 downloading） | GHCR 套件不是 Public；路由器本身 DNS 或對外連線有問題；外接碟空間不足 |
| 容器啟動後立刻停止，log 有 `load cert` | 憑證檔不存在或路徑錯誤 |
| log 有 `private key does not match public key` | `fullchain.pem` 第一張不是網域憑證，或 cert 與 key 不同組。用 `openssl x509 -in fullchain.pem -noout -subject` 檢查，依[第 4 步](#4-放入憑證並啟動)重新合併 |
| log 有 `permission denied` | 映像以 UID 65534 執行，掛載檔案權限不足。可在 Dockerfile 移除 `USER 65534` 重新打包 |
| 驗證頁出現但一直失敗，log 有 `"msg":"siteverify"`（`ERROR`） | 容器連不到外網：檢查 masquerade 是否涵蓋 `172.17.0.0/24`、DNS 是否可用（`/ip/dns` 的 `allow-remote-requests=yes`） |
| Turnstile 元件顯示錯誤 | Turnstile 後台沒加入此網域 |
| 直接打 IP 或用其他網域連線時 TLS 握手失敗（瀏覽器顯示連線被重設、`openssl s_client` 拿不到憑證） | 正常：嚴格 SNI 只接受 `ALLOWED_HOSTS`。改用網域連線，或確認 `domain` 沒打錯 |
| 連線得到 `421 misdirected request` | `Host` 不在 `ALLOWED_HOSTS`（例如 SNI 正確但 `Host` 填了別的）。確認 `domain` 沒打錯；瀏覽器碰到 421 會自動另開連線重試 |
| 自己被封鎖（連線被直接關閉，或回 `403 forbidden`） | 見 [blocking.md](blocking.md#解除封鎖誤封時)：重啟容器並刪除 `gate-block` 的項目 |
| log 有 `gate-blocklist: ...` warning | 容器沒在跑、沒設 `BLOCKLIST_LISTEN`，或缺少 `gate: blocklist replies` input 規則（拉取逾時）。用 `/tool/fetch url="http://172.17.0.2:9090/blocklist.json" output=user` 手動測試 |
| IPv6 連不上（`curl -6` 逾時），IPv4 正常 | AAAA 沒指向路由器 WAN 的 IPv6（或仍是 NAS 的位址，見 [IPv6](#ipv6)）；ISP 前綴變了但 AAAA 沒更新；`/ipv6/firewall/nat/print stats` 的 `gate: WAN443->gate` 沒有計數時，檢查 WAN 介面是否在 `WAN` interface list |
| 只有 IPv6 用戶端通過驗證後失敗，log 有 `"msg":"siteverify"` | 容器的 IPv6 出站不通：缺少 `gate: container masquerade`（NAT66），或 veth 沒有 `gateway6=fd17::1`。用 `/interface/veth/print` 確認位址與 gateway6 |
| 匯入時顯示「IPv6 防火牆沒有 forward／input 規則」 | 路由器沒有 IPv6 防火牆規則。先建立（至少要有 forward、input 規則，可參考 RouterOS 手冊 Building Advanced Firewall 的 IPv6 部分）再匯入 |
| 在家用網域連線失敗或很慢（裝置有 IPv6） | Split DNS 只設了 A：裝置拿到公開的 AAAA，先試 IPv6 連路由器 WAN 位址失敗才退回 IPv4。家裡改用 NAS 內網 IP 連線，或讓區網的 AAAA 解析到 NAS |
| 502 Bad Gateway | `UPSTREAM` 位址錯誤，或 forward 規則沒放行容器到 NAS:5001 |
| 502 Bad Gateway，log 有 `x509` 或 `failed to verify certificate` | DSM 5001 用的不是 `domain` 的有效憑證（自簽、其他網域或已過期），或 `domain` 打錯；路由器時間不正確也會讓憑證驗證失敗，用 `/system/clock/print` 確認並啟用 `/system/ntp/client` |

## 建議設定

| 項目 | 說明 |
|---|---|
| WireGuard 備援 | 在路由器開 WireGuard（`/interface/wireguard`）。閘門故障或自己被封鎖時能連回家修理；DS File、Synology Photos 等無法通過驗證頁的手機 App 也改走這條 |
| 外部監控 | 用 UptimeRobot 等服務檢查 `https://<網域>/__gate` 可連線與憑證到期日。驗證頁不需要 cookie，回 `200` 即正常；憑證推送失敗時能提早發現 |
| Split DNS | `/ip/dns/static/add name=<網域> address=<NAS IP>`，在家用網域連線時直接到 NAS，不需要 hairpin NAT。**會影響整個區網**：所有用路由器 DNS 的裝置都會解析到 NAS 內網 IP，繞過閘門直接連 DSM（區網本來就不經過閘門） |
| NTP | 確認 `/system/ntp/client` 已啟用。RB5009 沒有時鐘電池，時間錯會讓 cookie 與憑證驗證失效 |

## 移除

```
/container/stop [find comment="gate"]
/container/remove [find comment="gate"]
/container/envs/remove [find list="gate"]
/container/mounts/remove [find list="gate-cert"]
/ip/firewall/filter/remove [find comment~"gate"]
/ip/firewall/nat/remove [find comment~"gate"]
/ip/firewall/raw/remove [find comment~"gate"]
/ip/firewall/address-list/remove [find list="gate-block"]
/ipv6/firewall/filter/remove [find comment~"gate"]
/ipv6/firewall/nat/remove [find comment~"gate"]
/ipv6/firewall/raw/remove [find comment~"gate"]
/ipv6/firewall/address-list/remove [find list="gate-block"]
/system/scheduler/remove [find name="gate-blocklist"]
/system/script/remove [find name="gate-blocklist"]
/user/remove [find name="gatecert"]
/user/group/remove [find name="cert-push"]
/interface/bridge/port/remove [find interface="veth-gate"]
/interface/veth/remove [find name="veth-gate"]
/ip/address/remove [find interface="br-ct"]
/ipv6/address/remove [find interface="br-ct" comment="gate"]
/interface/bridge/remove [find name="br-ct"]
```
