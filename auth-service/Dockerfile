FROM golang:latest

ADD . /go/src/github.com/eecscord/workspace/auth-service

WORKDIR /go/src/github.com/eecscord/workspace/auth-service

RUN go mod download

RUN go build -o main .

CMD ["./main"]