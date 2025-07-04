# build stage (amd64)
FROM --platform=linux/amd64 golang:1.23 AS build
WORKDIR /app
COPY . .
RUN go mod init registrator && go mod tidy
RUN go build -o registrator -ldflags "-w -s" main.go

# tiny runtime (amd64)
FROM --platform=linux/amd64 gcr.io/distroless/base-debian12
COPY --from=build /app/registrator /usr/local/bin/registrator
ENTRYPOINT ["/usr/local/bin/registrator"]
