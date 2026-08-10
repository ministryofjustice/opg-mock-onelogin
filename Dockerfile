FROM golang:1.25-alpine3.23@sha256:cc985ef6f9c3bf9ece7488129c9abe0a150388ccdfa428d886fc709dca0b230a AS build-env

RUN apk --no-cache add openssl

RUN apk update busybox

WORKDIR /app

COPY --link go.mod go.sum ./
RUN go mod download

COPY --link main.go ./main.go
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -a -installsuffix cgo -o mock-onelogin .

RUN addgroup --system app && \
  adduser --system --gecos app app && \
  chown -R app:app /app

FROM scratch

COPY --from=build-env /app/mock-onelogin /app/mock-onelogin
COPY --from=build-env /etc/passwd /etc/passwd
COPY web web

USER app

CMD [ "/app/mock-onelogin" ]
