FROM golang:1.22.0-alpine as build-env

RUN apk --no-cache add openssl

WORKDIR /app

COPY --link go.mod go.sum ./
RUN go mod download

COPY --link cmd/mock-onelogin/main.go ./main.go
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o mock-onelogin .

FROM scratch

COPY --from=build-env /app/mock-onelogin /app/mock-onelogin
COPY web web

CMD [ "/app/mock-onelogin" ]
