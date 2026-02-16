all: build

.PHONY: build
build:
	podman build -t quay.io/bertinatto/redis-bench:v2 .
	podman push quay.io/bertinatto/redis-bench:v2
