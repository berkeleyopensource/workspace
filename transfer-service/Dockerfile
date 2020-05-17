FROM golang:latest

ADD . /go/src/github.com/berkeleyopensource/workspace/transfer-service

WORKDIR /go/src/github.com/berkeleyopensource/workspace/transfer-service

RUN go mod download

RUN go build -o main .

CMD ["./main"]