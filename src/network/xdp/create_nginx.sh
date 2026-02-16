#!/bin/bash


oc apply -f deploy.yaml
oc expose deployment http-server-1 --port=80 --target-port=80 --name=http-server-service-1
oc expose deployment http-server-2 --port=80 --target-port=80 --name=http-server-service-2

oc expose svc http-server-service-1
oc expose svc http-server-service-2

oc get routes -o json | jq -r '.items[] | select(.metadata.name == "http-server-service-1") | .spec.host'
oc get routes -o json | jq -r '.items[] | select(.metadata.name == "http-server-service-2") | .spec.host'


oc label namespace default openshift.io/cluster-monitoring=true
