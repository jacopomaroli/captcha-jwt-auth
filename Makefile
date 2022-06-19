BRANCH := $(shell git rev-parse --abbrev-ref HEAD)

check:
	cargo check

run:
	cargo run

build:
	cargo build --release --verbose

docker-build:
	docker build -t captcha-jwt-auth:${BRANCH} .

run-release:
	./target/release/captcha-jwt-auth
