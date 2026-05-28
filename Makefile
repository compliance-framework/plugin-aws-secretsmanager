.PHONY: build test

build:        ## Build the plugin binary
	go build -o plugin .

test:         ## Run tests
	go test ./...
