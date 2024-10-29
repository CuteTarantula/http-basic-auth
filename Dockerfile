# syntax=docker/dockerfile:1
FROM golang:1.23-alpine as builder
WORKDIR /build
ADD . .
RUN --mount=type=cache,target=/root/.cache/go-build go test ./... && CGO_ENABLED=0 go build -o ./bin/http-basic-auth ./main.go

FROM alpine
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/bin/http-basic-auth /app
EXPOSE 3322
ENTRYPOINT ["/app/http-basic-auth"]
