FROM golang:1.26-alpine3.23@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS build-env

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
