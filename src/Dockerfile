FROM golang:1.25-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/soc ./cmd/soc

FROM alpine:3.21

RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=build /out/soc /usr/local/bin/soc

EXPOSE 8080
ENTRYPOINT ["soc"]
CMD ["api"]