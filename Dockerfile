FROM golang:latest

# WORKDIR /go/src/app
# COPY . .

RUN apt-get install -y make
RUN go get -u github.com/golang/dep/cmd/dep
RUN go get -u github.com/alecthomas/gometalinter
RUN gometalinter --install
RUN make deps
RUN make check
RUN make test

# RUN go get -d -v ./...
# RUN go install -v ./...

# CMD ["app"]
