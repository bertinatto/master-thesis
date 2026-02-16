// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var podTrafficAnomaly = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "pod_network_traffic_anomaly",
		Help: "Indicates whether a pod is consuming anomalous network traffic (1 if anomalous, 0 otherwise)",
	},
	[]string{"pod_name", "namespace"},
)

func init() {
	prometheus.MustRegister(podTrafficAnomaly)
}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I../headers

func main() {

	// Expose Prometheus metrics at /metrics
	http.Handle("/metrics", promhttp.Handler())

	// Run the HTTP server in a separate goroutine
	go func() {
		log.Println("Starting HTTP server on :9101")
		if err := http.ListenAndServe(":9101", nil); err != nil {
			log.Fatalf("HTTP server failed: %v", err)
		}
	}()

	runtime := NewContainerRuntime()
	result, err := runtime.PS()
	if err != nil {
		log.Fatalf("Failed to get list of containers running on the node: %v", err)
	}

	interfaces, err := result.NetworkInterfaces("default")
	if err != nil {
		log.Fatalf("Failed to get network interfaces for pods: %v", err)

	}

	// Load pre-compiled programs into the kernel
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	for _, iface := range interfaces {
		l, err := link.AttachXDP(link.XDPOptions{
			Program:   objs.XdpProgFunc,
			Interface: iface.Index,
		})
		if err != nil {
			log.Fatalf("Could not attach XDP program to interface %q: %v", iface.Name, err)
		}
		defer l.Close()
		log.Printf("Attached XDP program to network interface %q (index %d)", iface.Name, iface.Index)
	}

	// Configure the detector with more sensitive parameters
	config := Config{
		WindowSize:           10,  // 10 seconds of history (shorter window to detect spikes faster)
		StdDevThreshold:      2.5, // Lower threshold (2.5 standard deviations)
		ConsecutiveAnomalies: 1,   // Detect single anomalies
		MinTrafficThreshold:  10,  // Minimum bytes to consider
	}

	detector := NewDetector(config)

	var anomalyTimestamps = make(map[string]time.Time)

	// Print the contents of the BPF hash map (net iface -> packet count)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		// s, err := formatMapContents(objs.XdpStatsMap)
		// if err != nil {
		// 	log.Printf("Error reading map: %s", err)
		// 	continue
		// }

		// log.Printf("Map contents:\n%s", s)

		traffic, err := getTraffic(objs.XdpStatsMap, result)
		if err != nil {
			log.Printf("bad traffic: %w", err)
			continue
		}

		// trafficPods := map[string]int64{}
		// for iface, bytes := range traffic {
		// 	for _, c := range result.Containers {
		// 		if iface == c.PodSandboxID[0:15] {
		// 			trafficPods[c.Labels.Name] = bytes
		// 		}
		// 	}
		// }

		// log.Printf("traffic: %v\n", traffic)

		// Process traffic and detect anomalies
		anomalous := detector.ProcessTraffic(traffic)
		// log.Printf("anamalous: %v\n", anomalous)

		// Sort and print pod names for consistent output
		// podNames := make([]string, 0, len(traffic))
		// for pod := range traffic {
		// 	podNames = append(podNames, pod)
		// }
		// sort.Slice(podNames, func(i, j int) bool {
		// 	return podNames[i] < podNames[j]
		// })

		// for pod, bytes := range traffic {
		// 	// fmt.Printf("  %-6s: %8d\n", pod, bytes)
		// 	if slices.Contains(anomalous, pod.Name) {
		// 		fmt.Printf("Anomaly detected: pod(%s) bytes(%d)\n", pod, bytes)
		// 		podTrafficAnomaly.WithLabelValues(pod.Name, pod.Namespace).Set(1)
		// 	} else {
		// 		podTrafficAnomaly.WithLabelValues(pod.Name, pod.Namespace).Set(0)
		// 	}
		// }

		const anomalyDuration = 30 * time.Second
		for pod, bytes := range traffic {
			now := time.Now()

			// Check if this pod is anomalous in the current cycle
			if slices.Contains(anomalous, pod.Name) {
				fmt.Printf("Anomaly detected: pod(%s) bytes(%d)\n", pod.Name, bytes)
				podTrafficAnomaly.WithLabelValues(pod.Name, pod.Namespace).Set(1)
				// Update or add the pod to the anomalyTimestamps map
				anomalyTimestamps[pod.Name] = now
			} else {
				// Check if the pod has an active anomaly in the map
				if lastDetected, ok := anomalyTimestamps[pod.Name]; ok {
					if now.Sub(lastDetected) <= anomalyDuration {
						// Keep the anomaly active
						fmt.Printf("Anomaly persists for pod(%s) bytes(%d)\n", pod.Name, bytes)
						podTrafficAnomaly.WithLabelValues(pod.Name, pod.Namespace).Set(1)
					} else {
						// Remove from anomalyTimestamps if 10 seconds have passed
						delete(anomalyTimestamps, pod.Name)
						podTrafficAnomaly.WithLabelValues(pod.Name, pod.Namespace).Set(0)
					}
				} else {
					// No anomaly detected, and it's not in the map
					podTrafficAnomaly.WithLabelValues(pod.Name, pod.Namespace).Set(0)
				}
			}
		}

		// log.Printf("podNames: %v\n", podNames)

		// log.Printf("podStats: %v\n", detector.podStats)

		// Print traffic data
		// for _, pod := range podNames {
		// 	bytes := traffic[pod]
		// 	fmt.Printf("  %-6s: %8d", pod, bytes)
		// 	if contains(anomalous, pod) {
		// 		fmt.Print(" 🚨 ANOMALY DETECTED!")
		// 	}
		// 	fmt.Println()
		// }
	}
}

type Pod struct {
	Name      string
	Namespace string
	Interface string
	Node      string
}

func getTraffic(m *ebpf.Map, r *Result) (map[Pod]int64, error) {
	var (
		key int32
		val datarec
	)
	result := map[Pod]int64{}
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		netIface, err := net.InterfaceByIndex(int(key))
		if err != nil {
			return nil, err
		}
		// result[netIface.Name] = int64(val.Bytes)
		for _, c := range r.Containers {
			if netIface.Name == c.PodSandboxID[0:15] {
				pod := Pod{
					Name:      c.Labels.Name,
					Namespace: c.Labels.Namespace,
				}
				result[pod] = int64(val.Bytes)
			}
		}

	}
	return result, nil
}

type datarec struct {
	Bytes    uint64
	LastSeen uint64
}

func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key int32
		val datarec
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		netIface, err := net.InterfaceByIndex(int(key))
		if err != nil {
			return "", err
		}

		packetCount := val.Bytes
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", netIface.Name, packetCount))
	}
	return sb.String(), iter.Err()
}
