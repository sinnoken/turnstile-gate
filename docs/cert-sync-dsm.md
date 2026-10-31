# 從 Synology DSM 自動同步憑證

DSM 已經會自動續期 Let's Encrypt 憑證。與其讓閘門再做一次 ACME，不如讓 DSM 續期後把憑證推給閘門。
腳本：[`deploy/dsm-push-cert.sh`](../deploy/dsm-push-cert.sh)

```
DSM（自動續期）──每天檢查，有變才 scp──→ MikroTik usb1/gate/cert/ ──1 分鐘內自動載入──→ turnstile-gate
```

> 為什麼要自動化：Let's Encrypt 憑證效期 90 天，CA/Browser Forum 也已通過逐年縮短憑證效期的決議，手動更新遲早會忘。

## 1. 找出要用的憑證

以 SSH 登入 DSM 並切換為 root：

```sh
mkdir -p /volume1/scripts/gate-cert && cd /volume1/scripts/gate-cert
# 放入 dsm-push-cert.sh
sh dsm-push-cert.sh --list
```

會列出每張憑證的 ID、網域與到期日。要用的不是預設憑證時，把 ID 填進腳本的 `CERT_ID`。

## 2. 建立 SSH 金鑰

```sh
ssh-keygen -t rsa -b 4096 -f id_gate -N ""
chmod 700 . && chmod 600 id_gate
```

把 `id_gate.pub` 上傳到路由器並綁定給 `gatecert`（帳號由 [`mikrotik-gate.rsc`](../deploy/mikrotik-gate.rsc) 建立）：

```
/user/ssh-keys/import public-key-file=id_gate.pub user=gatecert
```

綁定金鑰後，該帳號即無法用密碼登入。另確認 `/ip/service` 的 `ssh` 允許 NAS IP。

## 3. 修改腳本變數

```sh
ROUTER="192.168.88.1"
RUSER="gatecert"
DEST="usb1/gate/cert"
CERT_ID=""          # 空白 = DSM 預設憑證
```

## 4. 手動測試

```sh
sh dsm-push-cert.sh
```

成功會顯示 `已推送 subject=CN = ... notAfter=...`；再執行一次應顯示 `憑證未變動`。

## 5. 排程

**控制台 → 任務排程表 → 新增 → 排定的任務 → 使用者定義的指令碼**

- 使用者：`root`（讀取 `/usr/syno/etc/certificate` 需要）
- 排程：每天一次
- 指令：`sh /volume1/scripts/gate-cert/dsm-push-cert.sh`
- 設定 → 通知：填寫收件信箱並勾選 **僅在指令碼異常終止時寄送通知信**（DSM 介面寫法依版本略有不同，即「僅在異常終止時寄信」）。平常沒有信，推送失敗才會收到

> **萬用字元憑證**：建議在 DSM 申請 `*.your-domain`（例：`*.xxx.myds.me`）萬用字元憑證。Synology DDNS 網域在 DSM 申請 Let's Encrypt 時可勾選萬用字元，改走 DNS-01 驗證，**不需要對外開 80**；日後新增子網域也只要這一張。閘門與 `UPSTREAM_SERVER_NAME` 都能直接使用萬用字元憑證；萬用字元不涵蓋網域本身，用 `openssl x509 -in fullchain.pem -noout -ext subjectAltName` 確認同時列出 `your-domain` 與 `*.your-domain`。

## 運作細節

- 不使用 DSM 的 `fullchain.pem`（雙憑證 RSA + ECC 時它只有中繼與根憑證，不含網域憑證），改以 `cert.pem + chain.pem` 自行組成；推送前檢查網域憑證與 `privkey.pem` 成對，不成對就不推。
- 以組好的 `fullchain.pem + privkey.pem` 的 SHA-256 判斷是否變動，沒變就不連線。
- 先傳私鑰、再傳 fullchain。閘門以 fullchain 的修改時間判斷是否重新載入；若載入失敗（例如兩個檔案暫時不成對）會繼續使用舊憑證，並在下一分鐘重試。
- 第一次連線會記錄路由器的 host key 到 `known_hosts`，之後若 host key 改變會拒絕連線。

## 疑難排解

| 症狀 | 處理 |
|---|---|
| `Permission denied (publickey)` | 金鑰沒綁到 `gatecert`，或 `/ip/service ssh` 不允許 NAS IP |
| 上傳被拒 | 把 `cert-push` 群組的 policy 加上 `write` 再試 |
| `找不到憑證` | 用 `--list` 確認 ID，填入 `CERT_ID` |
| OpenSSH 9+ 的 scp 出錯 | 在 `scp` 加上 `-O` 改用舊版協定 |
