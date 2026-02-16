.PHONY: all
all: build

.PHONY: clean
clean:
	rm output/*.csv

.PHONY: build
build:
	gcc src/single.c -o bin/single

.PHONY: baseline
baseline:
	bash run.sh -f output/baseline.csv

.PHONY: bpf
bpf:
	bash run.sh -f output/bpf.csv

.PHONY: bpf-no-trace
bpf-no-trace:
	bash run.sh -f output/bpf_no_trace.csv
