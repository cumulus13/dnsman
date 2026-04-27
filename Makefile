APP     := dnsman
VERSION := 1.0.0
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w \
           -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.date=$(DATE)

.PHONY: build build-windows run clean install

## build: build for current OS
build:
	go build -ldflags "$(LDFLAGS)" -o $(APP) .

## build-windows: cross-compile for Windows (amd64)
build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(APP).exe .

## run: run with arguments, e.g. make run ARGS="show"
run:
	go run . $(ARGS)

## install: install to GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" .

## tidy: tidy modules
tidy:
	go mod tidy

## clean: remove built binaries
clean:
	rm -f $(APP) $(APP).exe

## help: print this help
help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
