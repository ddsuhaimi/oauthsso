.PHONY: all build run clean docker docker-run test

APP_NAME=oauthsso

all: build

build:
	go build -o $(APP_NAME) .

run:
	go run main.go

clean:
	rm -f $(APP_NAME)

docker:
	docker build -t $(APP_NAME) .

docker-run:
	docker run -p 8080:8080 $(APP_NAME)

test:
	go test -v ./...

tidy:
	go mod tidy 