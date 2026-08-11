.PHONY: build test vet fmt check run

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

fmt:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt found unformatted files" && exit 1)

check: build vet fmt test

run:
	go run ./cmd/authd
