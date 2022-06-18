BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

check:
	cargo check

run:
	cargo run

docker-build:
	docker build -t captcha-jwt-auth:${BRANCH} .
