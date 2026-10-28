#!/bin/sh
# 把 DSM 自動續期的 Let's Encrypt 憑證推送到 MikroTik（憑證有變才推）
# DSM「任務排程表」→ 使用者定義的腳本，使用者選 root，每天執行一次
#
#   bash /volume1/scripts/gate-cert/dsm-push-cert.sh
#   bash /volume1/scripts/gate-cert/dsm-push-cert.sh --list   # 列出 DSM 上的憑證與網域

ROUTER="192.168.88.1"                         # MikroTik 內網 IP
RUSER="gatecert"
DEST="usb1/gate/cert"                          # 跟 .rsc 裡的 $disk/gate/cert 一致
BASE="/volume1/scripts/gate-cert"
KEY="$BASE/id_gate"                            # ssh-keygen 產生的私鑰
STATE="$BASE/last.sha256"
CERT_ID=""                                     # 留空 = DSM 的預設憑證

ARCHIVE="/usr/syno/etc/certificate/_archive"

if [ "$1" = "--list" ]; then
    echo "預設憑證 ID: $(cat "$ARCHIVE/DEFAULT" 2>/dev/null)"
    for d in "$ARCHIVE"/*/; do
        [ -f "$d/cert.pem" ] || continue
        echo "== $(basename "$d")"
        openssl x509 -in "$d/cert.pem" -noout -subject -enddate
        openssl x509 -in "$d/cert.pem" -noout -ext subjectAltName 2>/dev/null | tail -n +2
    done
    exit 0
fi

[ -n "$CERT_ID" ] || CERT_ID="$(cat "$ARCHIVE/DEFAULT")"
DIR="$ARCHIVE/$CERT_ID"
[ -f "$DIR/fullchain.pem" ] && [ -f "$DIR/privkey.pem" ] || { echo "找不到憑證：$DIR"; exit 1; }

NEW="$(cat "$DIR/fullchain.pem" "$DIR/privkey.pem" | sha256sum | cut -d' ' -f1)"
[ "$NEW" = "$(cat "$STATE" 2>/dev/null)" ] && { echo "憑證未變動"; exit 0; }

SSH_OPTS="-i $KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$BASE/known_hosts"

# 先傳私鑰、再傳 fullchain（閘門以 fullchain 的修改時間判斷是否重新載入）
scp $SSH_OPTS "$DIR/privkey.pem"   "$RUSER@$ROUTER:$DEST/privkey.pem"   || exit 1
scp $SSH_OPTS "$DIR/fullchain.pem" "$RUSER@$ROUTER:$DEST/fullchain.pem" || exit 1

echo "$NEW" > "$STATE"
echo "已推送 $(openssl x509 -in "$DIR/cert.pem" -noout -subject -enddate | tr '\n' ' ')"
