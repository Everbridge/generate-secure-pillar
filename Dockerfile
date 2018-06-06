FROM golang:latest

# WORKDIR /go/src/app
# COPY . .

RUN apt-get install -y make
RUN go get -u github.com/golang/dep/cmd/dep && \
    go get -u github.com/alecthomas/gometalinter && \
    gometalinter --install
# RUN go get -d -v ./...
# RUN go install -v ./...

# CMD ["app"]
