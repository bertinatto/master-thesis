export BPF_CLANG=clang

.PHONY: all
all: build

.PHONY: build
build:
	go generate
	go build

.PHONY: run
run: build
	sudo ./xdp wlp0s20f3

.PHONY: deploy
IMAGE=
deploy: build
	podman build -t quay.io/bertinatto/xdp:latest .
	podman push quay.io/bertinatto/xdp:latest
	oc delete -f ds.yaml
	oc apply -f ds.yaml
	oc get pods -o wide
