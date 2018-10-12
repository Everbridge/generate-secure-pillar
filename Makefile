SHELL := /usr/bin/env bash

PATH := $(PATH):/usr/local/bin

# The name of the executable (default is current directory name)
TARGET := $(shell echo $${PWD\#\#*/})
.DEFAULT_GOAL: $(TARGET)

# These will be provided to the target
BUILD := `git rev-parse HEAD`
COMMIT := `git rev-list HEAD | wc -l | sed 's/^ *//g'`
VERSION := 1.0.$(COMMIT)

# Use linker flags to provide version/build settings to the target
LDFLAGS=-ldflags "-X=main.Version=$(VERSION) -X=main.Build=$(BUILD)"

# go source files, ignore vendor directory
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")

RELEASER := $(shell command -v goreleaser 2> /dev/null)
REVIVE := $(shell command -v revive 2> /dev/null)
FPM := $(shell command -v fpm 2> /dev/null)

BRANCH := `git rev-parse --abbrev-ref HEAD`

GOROOT := `go env GOROOT`

.PHONY: all build clean install uninstall fmt simplify check run

all: build install

$(TARGET): $(SRC)
	@go build $(LDFLAGS) -o $(TARGET)

build: deps check test
	@go build

release: build $(TARGET)
	@cat cmd/root.go | sed 's/\"1.0.*\"/\"1.0.'$(COMMIT)'\"/' > cmd/root.go
	@cat README.md | sed 's/VERSION 1.0.*/VERSION 1.0.'$(COMMIT)'/' > README.md
	@git commit -am "new $(BRANCH) build: $(VERSION)"
	@git tag -a v$(VERSION) -m "new $(BRANCH) build: $(VERSION)"
	@echo pushing to branch $(BRANCH)
	@git push origin v$(VERSION)
	@git push origin $(BRANCH)
ifndef RELEASER
	@echo "cannot build release (missing goreleaser)"
else
	@echo "creating a new release"
	GITHUB_TOKEN=`~/.config/goreleaser/github_token` goreleaser --rm-dist
endif
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
ifndef REVIVE
	@echo "running 'golint .'"
	@golint .
else
	@echo "running 'revive ./...'"
	@revive --formatter friendly ./...
endif

run: install
	@$(TARGET)

test:
	@go test -v

deps:
	@go mod init | true
	@go mod tidy
	@go mod verify

mac: GOOS = darwin
mac: GOARCH = amd64
mac:
	@echo "building for $(GOOS)/$(GOARCH)"
	@mkdir -p bin/$(GOARCH)/$(GOOS)/ && GOOS=$(GOOS) GOARCH=$(GOARCH) go build && mv $(TARGET) bin/$(GOARCH)/$(GOOS)/

ubuntu: GOOS = linux
ubuntu: GOARCH = amd64
ubuntu:
	@echo "building for $(GOOS)/$(GOARCH)"
	@mkdir -p bin/$(GOARCH)/$(GOOS)/ && GOOS=$(GOOS) GOARCH=$(GOARCH) go build && mv $(TARGET) bin/$(GOARCH)/$(GOOS)/

packages: deb pkg

deb: GOOS = linux
deb: GOARCH = amd64
deb: ubuntu
ifndef FPM
	@echo "'fpm' is not installed, cannot make packages"
else
	@fpm -n $(TARGET) -s dir -t deb -a $(GOARCH) -p $(TARGET)_$(VERSION)_$(GOARCH).deb --deb-no-default-config-files ./bin/$(GOARCH)/$(GOOS)/$(TARGET)=/usr/local/bin/$(TARGET)
	@mv $(TARGET)*.deb ./packages
endif

pkg: GOOS = darwin
pkg: GOARCH = amd64
pkg: mac
ifndef FPM
	@echo "'fpm' is not installed, cannot make packages"
else
	@fpm -n $(TARGET) -s dir -t osxpkg -a $(GOARCH) -p $(TARGET)-$(VERSION)-$(GOARCH).pkg ./bin/$(GOARCH)/$(GOOS)/$(TARGET)=/usr/local/bin/$(TARGET)
	@mv $(TARGET)*.pkg ./packages
endif
