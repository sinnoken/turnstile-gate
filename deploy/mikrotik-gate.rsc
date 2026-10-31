# turnstile-gate on MikroTik RouterOS v7 (e.g. RB5009 / arm64)
# 說明文件：docs/deploy-mikrotik.md
# 用法：先改下面的變數 → 上傳到路由器 → /import mikrotik-gate.rsc
# 所有新增項目的 comment 或名稱都含 "gate"，方便日後查找/移除（script 以名稱 gate-blocklist 辨識）
{
:local nasIP   "192.168.88.10"      ;# NAS 的內網 IP
:local domain  "nas.example.com"    ;# 你的網域；DSM 5001 的憑證必須是這個網域的
:local disk    "usb1"               ;# /disk print 看外接碟名稱
:local image   "ghcr.io/sinnoken/turnstile-gate:latest"   ;# 路由器直接從 GHCR 拉映像
:local siteKey "0x4AAAA_SITEKEY"
:local secret  "0x4AAAA_SECRET"
:local gateKey ""                   ;# 留空＝匯入時自動產生；要自訂請填 openssl rand -hex 32 的結果

# cookie 簽章金鑰：留空（或仍是舊範本的佔位字串）就用 :rndstr 產生 64 字元 hex，絕不使用公開的固定值
:if (($gateKey = "") || ($gateKey = "REPLACE_WITH_openssl_rand_hex_32")) do={
    :set gateKey [:rndstr length=64 from="0123456789abcdef"]
    :put "已自動產生 GATE_KEY（會存入 /container/envs list=gate）"
}

# ---------- 1. 容器網路 ----------
/interface/bridge/add name=br-ct comment="gate"
/ip/address/add address=172.17.0.1/24 interface=br-ct comment="gate"
/interface/veth/add name=veth-gate address=172.17.0.2/24 gateway=172.17.0.1 comment="gate"
/interface/bridge/port/add bridge=br-ct interface=veth-gate comment="gate"
# 注意：br-ct 不要加進 LAN interface list

# ---------- 2. 對外：WAN 443 → gate 8443 ----------
/ip/firewall/nat/add chain=dstnat in-interface-list=WAN protocol=tcp dst-port=443 \
    action=dst-nat to-addresses=172.17.0.2 to-ports=8443 comment="gate: WAN443->gate"

# ---------- 3. forward：速率限制 + 容器隔離（插在最上面，依序排列） ----------
:local fTop [:pick [/ip/firewall/filter/find chain=forward dynamic=no] 0]
/ip/firewall/filter/add place-before=$fTop chain=forward action=drop \
    dst-address=172.17.0.2 protocol=tcp dst-port=8443 connection-state=new \
    connection-limit=20,32 comment="gate: per-IP max 20 conns"
/ip/firewall/filter/add place-before=$fTop chain=forward action=accept \
    dst-address=172.17.0.2 protocol=tcp dst-port=8443 connection-state=new \
    dst-limit=30/1m,60,src-address/10m comment="gate: per-IP 30 new conn/min"
/ip/firewall/filter/add place-before=$fTop chain=forward action=drop \
    dst-address=172.17.0.2 protocol=tcp dst-port=8443 connection-state=new \
    comment="gate: over rate limit"
/ip/firewall/filter/add place-before=$fTop chain=forward action=accept \
    src-address=172.17.0.2 dst-address=$nasIP protocol=tcp dst-port=5001 \
    comment="gate: container -> DSM 5001"
/ip/firewall/filter/add place-before=$fTop chain=forward action=accept \
    src-address=172.17.0.2 out-interface-list=WAN protocol=tcp dst-port=443 \
    comment="gate: container -> internet 443 (siteverify)"
/ip/firewall/filter/add place-before=$fTop chain=forward action=drop \
    src-address=172.17.0.0/24 connection-state=new \
    comment="gate: container isolation"
# 封鎖清單 9090 只給路由器自己拉（路由器發出的是 output，不經 forward）；區網其他主機一律擋
/ip/firewall/filter/add place-before=$fTop chain=forward action=drop \
    dst-address=172.17.0.2 protocol=tcp dst-port=9090 \
    comment="gate: blocklist router only"

# ---------- 4. input：容器只能用路由器的 DNS，其他一律擋 ----------
:local iTop [:pick [/ip/firewall/filter/find chain=input dynamic=no] 0]
/ip/firewall/filter/add place-before=$iTop chain=input action=accept \
    src-address=172.17.0.2 protocol=udp dst-port=53 comment="gate: DNS udp"
/ip/firewall/filter/add place-before=$iTop chain=input action=accept \
    src-address=172.17.0.2 protocol=tcp dst-port=53 comment="gate: DNS tcp"
# 路由器拉封鎖清單時，容器回的封包走 input；要排在下面那條 drop 之前
/ip/firewall/filter/add place-before=$iTop chain=input action=accept \
    src-address=172.17.0.2 protocol=tcp src-port=9090 \
    connection-state=established,related comment="gate: blocklist replies"
/ip/firewall/filter/add place-before=$iTop chain=input action=drop \
    src-address=172.17.0.0/24 comment="gate: no router access"

# ---------- 5. 給 DSM 推送憑證用的帳號（只允許 NAS 登入） ----------
/user/group/add name=cert-push policy=ssh,ftp,read comment="gate"
/user/add name=gatecert group=cert-push address="$nasIP/32" \
    password=[:rndstr length=40 from="abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"] \
    comment="gate: DSM cert push (key login only)"

# ---------- 6. 容器 ----------
/container/config/set memory-high=128M tmpdir="$disk/tmp"
/container/envs/add list=gate key=TURNSTILE_SITEKEY value=$siteKey
/container/envs/add list=gate key=TURNSTILE_SECRET  value=$secret
/container/envs/add list=gate key=GATE_KEY          value=$gateKey
/container/envs/add list=gate key=UPSTREAM          value="https://$nasIP:5001"
/container/envs/add list=gate key=UPSTREAM_SERVER_NAME value=$domain
/container/envs/add list=gate key=ALLOWED_HOSTS     value=$domain
/container/envs/add list=gate key=BLOCKLIST_LISTEN  value="172.17.0.2:9090"
# 憑證（/cert/fullchain.pem、/cert/privkey.pem）、GOMEMLIMIT=48MiB、SESSION_HOURS=12 都是映像的預設值
/container/mounts/add list=gate-cert src="$disk/gate/cert" dst=/cert mode=ro
/container/add remote-image=$image check-certificate=yes interface=veth-gate envlists=gate \
    mountlists=gate-cert root-dir="$disk/gate/root" dns=172.17.0.1 \
    logging=yes start-on-boot=yes comment="gate"

# ---------- 7. 封鎖清單：每分鐘拉閘門的 /blocklist.json，寫進有時效的 address-list gate-block ----------
# source={ } 是程式區塊，匯入時不展開 $ 變數，不需要跳脫；區塊內的變數都在區塊內宣告
# 拉取或解析失敗只記一行 warning，既有項目照 timeout 到期，下一分鐘再試
/system/script/add name=gate-blocklist source={
    :onerror e in={
        :local r [/tool/fetch url="http://172.17.0.2:9090/blocklist.json" output=user as-value]
        :local j [:deserialize from=json value=($r->"data")]
        :foreach it in=($j->"items") do={
            :local ip ($it->"ip")
            :local t [:totime (($it->"ttl") . "s")]
            :local c ("gate: " . ($it->"event") . " #" . ($it->"strike"))
            :local id [/ip/firewall/address-list/find list=gate-block address=$ip]
            :if ([:len $id] = 0) do={
                /ip/firewall/address-list/add list=gate-block address=$ip timeout=$t comment=$c
            } else={
                /ip/firewall/address-list/set $id timeout=$t comment=$c
            }
        }
    } do={ :log warning "gate-blocklist: $e" }
}
/system/scheduler/add name=gate-blocklist interval=1m on-event=gate-blocklist comment="gate"
/ip/firewall/raw/add chain=prerouting in-interface-list=WAN src-address-list=gate-block \
    action=drop comment="gate: blocklist"

:put "OK。等 /container/print 顯示 stopped（下載與解壓完成）後，且憑證已推送，再執行："
:put "/container/start [find comment=\"gate\"]"
}
