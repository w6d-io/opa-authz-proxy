FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /opa-authz-proxy .

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /opa-authz-proxy /opa-authz-proxy
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/opa-authz-proxy"]
