all: deploy

.PHONY: deploy
deploy:
	oc delete -f deploy.yaml
	oc apply -f deploy.yaml

.PHONY: build
build:
	cd bench/ && make build
