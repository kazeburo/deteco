VERSION=0.0.5
LDFLAGS=-ldflags "-X main.Version=${VERSION}"

all: deteco

.PHONY: deteco

bundle:
	dep ensure

update:
	dep ensure -update

deteco: cli/deteco/main.go deteco/*.go
	go build $(LDFLAGS) -o bin/deteco cli/deteco/main.go

linux: cli/deteco/main.go deteco/*.go
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/deteco cli/deteco/main.go

check:
	go test ./...

fmt:
	go fmt ./...

tag:
	git tag v${VERSION}
	git push origin v${VERSION}
	git push origin master
	goreleaser --rm-dist
