SHELL := /bin/bash

# The name of the executable (default is current directory name)
TARGET := $(shell echo $${PWD\#\#*/})
.DEFAULT_GOAL: $(TARGET)

# These will be provided to the target
VERSION := 1.0.0
BUILD := `git rev-parse HEAD`

# Use linker flags to provide version/build settings to the target
LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

# go source files, ignore vendor directory
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

.PHONY: all build clean install uninstall fmt simplify check run

all: check install

$(TARGET): $(SRC)
	@go build $(LDFLAGS) -o $(TARGET)

build: deps $(TARGET)
	@true

clean:
	@rm -f $(TARGET)
	$(shell find ./bin -type f -perm +111 -delete)

install:
	@go install $(LDFLAGS)

uninstall: clean
	@rm -f $$(which ${TARGET})

fmt:
	@gofmt -l -w $(SRC)

simplify:
	@gofmt -s -l -w $(SRC)

check:
	@test -z $(shell gofmt -l main.go | tee /dev/stderr) || echo "[WARN] Fix formatting issues with 'make fmt'"
	@gometalinter --vendor ./...

run: install
	@$(TARGET)

test:
	@go test -v

deps:
	@dep ensure -update

mac: GOOS = darwin
mac: GOARCH = amd64
mac:
	@echo "building for $(GOOS)/$(GOARCH)"
	@mkdir -p bin/$(GOARCH)/$(GOOS)/ && go build && mv $(TARGET) bin/$(GOARCH)/$(GOOS)/

ubuntu: GOOS = linux
ubuntu: GOARCH = amd64
ubuntu:
	@echo "building for $(GOOS)/$(GOARCH)"
	@mkdir -p bin/$(GOARCH)/$(GOOS)/ && go build && mv $(TARGET) bin/$(GOARCH)/$(GOOS)/

packages: deb pkg

deb: GOOS = linux
deb: GOARCH = amd64
deb: ubuntu
	fpm -n $(TARGET) -s dir -t deb -p $(TARGET)_VERSION_$(GOARCH).deb --deb-no-default-config-files ./bin/$(GOARCH)/$(GOOS)/$(TARGET)=/usr/local/bin/$(TARGET)
	@mv $(TARGET)*.deb ./packages

pkg: GOOS = darwin
pkg: GOARCH = amd64
pkg: mac
	@fpm -n $(TARGET) -s dir -t osxpkg ./bin/$(GOARCH)/$(GOOS)/$(TARGET)=/usr/local/bin/$(TARGET)
	@mv $(TARGET)*.pkg ./packages
