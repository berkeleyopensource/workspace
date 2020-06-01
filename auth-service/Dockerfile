FROM golang:latest
ADD . /go/src/github.com/berkeleyopensource/workspace/auth-service
WORKDIR /go/src/github.com/berkeleyopensource/workspace/auth-service
RUN go mod download
RUN go build -o main .
EXPOSE 80
ENTRYPOINT [ "./main" ]