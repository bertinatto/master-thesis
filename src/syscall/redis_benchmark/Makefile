.PHONY: baseline
baseline:
	redis-benchmark -h localhost -p 6379 --csv > redis_baseline.csv

.PHONY: bpf
bpf:
	redis-benchmark -h localhost -p 6379 --csv > redis_bpf.csv
