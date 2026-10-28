# turnstile-gate on MikroTik RouterOS v7 (e.g. RB5009 / arm64)
# 說明文件：docs/deploy-mikrotik.md
# 用法：先改下面的變數 → 上傳到路由器 → /import mikrotik-gate.rsc
# 所有新增項目都有 comment 含 "gate"，方便日後查找/移除
{
:local nasIP   "192.168.88.10"      ;# NAS 的內網 IP
:local disk    "usb1"               ;# /disk print 看外接碟名稱
:local image   "ghcr.io/sinnoken/turnstile-gate:latest"   ;# 路由器直接從 GHCR 拉映像
:local siteKey "0x4AAAA_SITEKEY"
:local secret  "0x4AAAA_SECRET"
:local gateKey "REPLACE_WITH_openssl_rand_hex_32"

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

# ---------- 4. input：容器只能用路由器的 DNS，其他一律擋 ----------
:local iTop [:pick [/ip/firewall/filter/find chain=input dynamic=no] 0]
/ip/firewall/filter/add place-before=$iTop chain=input action=accept \
    src-address=172.17.0.2 protocol=udp dst-port=53 comment="gate: DNS udp"
/ip/firewall/filter/add place-before=$iTop chain=input action=accept \
    src-address=172.17.0.2 protocol=tcp dst-port=53 comment="gate: DNS tcp"
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
/container/envs/add list=gate key=UPSTREAM_INSECURE value="1"
/container/envs/add list=gate key=CERT_FILE         value="/cert/fullchain.pem"
/container/envs/add list=gate key=KEY_FILE          value="/cert/privkey.pem"
/container/envs/add list=gate key=SESSION_HOURS     value="12"
/container/mounts/add list=gate-cert src="$disk/gate/cert" dst=/cert mode=ro
/container/add remote-image=$image check-certificate=yes interface=veth-gate envlists=gate \
    mountlists=gate-cert root-dir="$disk/gate/root" dns=172.17.0.1 \
    logging=yes start-on-boot=yes comment="gate"

:put "OK。等 /container/print 顯示 stopped（下載與解壓完成）後，且憑證已推送，再執行："
:put "/container/start [find comment=\"gate\"]"
}
