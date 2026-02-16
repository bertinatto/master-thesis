#!/bin/bash


oc apply -f deploy_redis.yaml
oc expose deployment redis-server-1 --port=6379 --target-port=6379 --name=redis-server-service-1

# oc expose svc redis-server-service-1

# oc get routes -o json | jq -r '.items[] | select(.metadata.name == "redis-server-service-1") | .spec.host'

oc label namespace default openshift.io/cluster-monitoring=true
