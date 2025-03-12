FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder
LABEL maintainer="nekolsd <nekolsd@proton.me>"
COPY . /go/src/github.com/nekolsd/sing-box
WORKDIR /go/src/github.com/nekolsd/sing-box
ARG TARGETOS TARGETARCH
ARG GOPROXY=""
ENV GOPROXY=$GOPROXY
ENV CGO_ENABLED=0
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH
ENV GODEBUG="asynctimerchan=1"
RUN set -ex \
    && apk add git build-base \
    && export COMMIT=$(git rev-parse --short HEAD) \
    && export VERSION=$(go run ./cmd/internal/read_tag) \
    && go build -v -trimpath -tags \
        "with_quic,with_dhcp,with_wireguard,with_utls,with_reality_server,with_acme,with_clash_api,with_v2ray_api,with_gvisor,with_conntrack" \
        -o /go/bin/sing-box \
        -ldflags "-X \"github.com/sagernet/sing-box/constant.Version=$VERSION\" -s -w -buildid=" \
        ./cmd/sing-box
FROM --platform=$TARGETPLATFORM alpine AS dist
LABEL maintainer="nekolsd <nekolsd@proton.me>"
RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata ca-certificates nftables \
    && rm -rf /var/cache/apk/*
COPY --from=builder /go/bin/sing-box /usr/local/bin/sing-box
ENTRYPOINT ["sing-box"]
