FROM docker.io/library/golang:latest AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o redis-bench

FROM fedora
WORKDIR /root/
COPY --from=builder /app/redis-bench .
RUN dnf install --nodocs -y fpaste valkey-compat-redis nc  && dnf clean all
#CMD ["./redis-bench"]
