FROM golang:latest

ADD . /go/src/github.com/eecscord/workspace/go

WORKDIR /go/src/github.com/eecscord/workspace/go

RUN go mod download

RUN go build -o main .

CMD ["./main"]