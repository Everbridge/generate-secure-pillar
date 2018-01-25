SHELL := /bin/bash

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

METALINT := $(shell command -v gometalinter 2> /dev/null)
DEP := $(shell command -v dep 2> /dev/null)
FPM := $(shell command -v fpm 2> /dev/null)

.PHONY: all build clean install uninstall fmt simplify check run

all: check build install

$(TARGET): $(SRC)
	@go build $(LDFLAGS) -o $(TARGET)

build: deps $(TARGET)
	@cat main.go | sed 's/\"1.0.*\"/\"1.0.'$(COMMIT)'\"/' > main.go
	@go build
	./generate-secure-pillar -h > README.txt
	@rm generate-secure-pillar
	@make pkg deb
	@git commit -am 'new build'
	@git push origin master
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
ifndef METALINT
	@echo "running 'go lint .'"
	@golint .
else
	@echo "running 'gometalinter ./...'"
	@gometalinter --vendor ./...
endif

run: install
	@$(TARGET)

test:
	@go test -v

deps:
ifndef DEP
	@echo "'dep' is not installed, cannot ensure dependencies are installed"
else
	@dep ensure -update
endif

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
ifndef DEP
	@echo "'fpm' is not installed, cannot make packages"
else
	@fpm -n $(TARGET) -s dir -t deb -a $(GOARCH) -p $(TARGET)_VERSION_$(GOARCH).deb --deb-no-default-config-files ./bin/$(GOARCH)/$(GOOS)/$(TARGET)=/usr/local/bin/$(TARGET)
	@mv $(TARGET)*.deb ./packages
endif

pkg: GOOS = darwin
pkg: GOARCH = amd64
pkg: mac
ifndef DEP
	@echo "'fpm' is not installed, cannot make packages"
else
	@fpm -n $(TARGET) -s dir -t osxpkg -a $(GOARCH) ./bin/$(GOARCH)/$(GOOS)/$(TARGET)=/usr/local/bin/$(TARGET)
	@mv $(TARGET)*.pkg ./packages
endif
