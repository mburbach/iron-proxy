FROM golang:1.27.3-alpine AS build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /iron-proxy ./cmd/iron-proxy

FROM alpine:latest
RUN apk add --no-cache ca-certificates openssl \
    && sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt$|!&|' \
              -e 's|^mozilla/Comodo_AAA_Services_root.crt$|!&|' /etc/ca-certificates.conf \
    && update-ca-certificates
COPY --from=build /iron-proxy /usr/local/bin/iron-proxy
COPY examples/nftables/proxy.yaml /etc/iron-proxy/proxy.yaml
COPY examples/docker-compose/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
