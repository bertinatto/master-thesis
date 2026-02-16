# How to run experiments

First deploy the Redis server and the container containing the benchmark tools:

```sh
cd redis
make deploy
```

Get the IP address of where Redis server can be accessed:

```sh
oc get svc
```

Connect to the benchmark container and run the benchmark tools:

```sh
# redis-benchmark
redis-benchmark -h ip_from_svc -p 6379 --csv > baseline.csv

# benchmark tools that measure latencies
./redis-bench -host ip_from_svc -port 6379 -prefix baseline
```

Repeat the previous steps to get the eBPF results, however, this time deploy the eBPF solution before running the benchmark tools:

```sh
cd xdp
make deploy
```
