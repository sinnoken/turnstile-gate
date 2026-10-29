# 最小化映像（scratch），適合 RouterOS container 這種儲存空間有限的環境
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS TARGETARCH TARGETVARIANT
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /gate .

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /gate /gate
USER 65534
# 路由器等記憶體有限的環境；需要時可用環境變數覆寫
ENV GOMEMLIMIT=48MiB
EXPOSE 8443
ENTRYPOINT ["/gate"]
