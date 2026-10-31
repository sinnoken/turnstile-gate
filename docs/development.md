# 開發與測試

給要修改程式或送 PR 的人。使用者自行建置執行檔或映像見 [README 建置](../README.md#建置)。

## 原則

- 單一 `main.go`、只用 Go 標準函式庫，不引入第三方套件。
- 文件與程式註解用繁體中文（台灣用語）。
- 改了行為就在同一個 commit 更新對應的規格文件（見 [文件索引](README.md)）。

## 指令

```bash
go vet ./...
go test ./...                              # 不需要任何環境變數
go test -run TestSafeNext -v ./...         # 單一測試
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null .   # 路由器的目標架構
```

`go test -race` 需要 cgo，本機沒有 C 編譯器時交給 CI。

`main.go`、`Dockerfile`、`README.md` 使用 CRLF 換行，編輯時保持原樣；gofmt 檢查可先轉成 LF 副本：

```bash
tr -d '\r' < main.go > /tmp/x.go && gofmt -l /tmp/x.go
```

## CI

`.github/workflows/build.yml`：

| job | 內容 |
|---|---|
| `test` | `go vet`、`go test -race`、`govulncheck`、建置 |
| `image` | 多架構映像推到 GHCR（`main` → `:latest`；`v*` tag → 版本映像） |
| `routeros-tar` | `arm64`、`armv7`、`amd64` 的 RouterOS 匯入用 tar |
| `release` | 只在 `v*` tag 建立 Release，附 tar 與 SHA-256 |

另有每週排程重建，帶入 Go 與基底映像的修補。action 釘選完整 commit SHA（註解標版本），由 dependabot 每週更新。

升級 Go 時 `go.mod` 與 `Dockerfile` 的 `golang:<版本>-alpine` 一起改；Go 只維護最新兩個大版本，舊版的標準函式庫漏洞會讓 `govulncheck` 失敗。

## 驗證頁

驗證頁的 CSS／JS 內嵌在 `main.go` 的樣板裡，要在真的瀏覽器看淺色與深色模式，curl 測不出樣式錯誤。標題字型 `fonts/gate-heading.woff2` 是只含標題文字的子集，**改標題文字就要重新產生子集**（授權見 `fonts/OFL.txt`）。
