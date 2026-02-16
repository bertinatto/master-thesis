package main

import (
	"fmt"
	"math"
	"math/rand"
	"time"
)

// Config holds the configuration parameters for anomaly detection
type Config struct {
	WindowSize           int
	StdDevThreshold      float64
	ConsecutiveAnomalies int
	MinTrafficThreshold  int64
}

// PodStats maintains statistics for a single pod
type PodStats struct {
	readings     []int64
	position     int
	sum          int64
	sumSq        float64
	count        int
	anomalyCount int
	lastUpdate   time.Time
}

// Detector handles anomaly detection for multiple pods
type Detector struct {
	config    Config
	podStats  map[string]*PodStats
	timestamp time.Time
}

// NewDetector creates a new anomaly detector with specified configuration
func NewDetector(config Config) *Detector {
	return &Detector{
		config:   config,
		podStats: make(map[string]*PodStats),
	}
}

// ProcessTraffic analyzes new traffic data and returns pods with anomalous behavior
func (d *Detector) ProcessTraffic(traffic map[string]int64) []string {
	currentTime := time.Now()

	var totalTraffic int64
	activePodsCount := 0
	for _, bytes := range traffic {
		if bytes >= d.config.MinTrafficThreshold {
			totalTraffic += bytes
			activePodsCount++
		}
	}

	if activePodsCount == 0 {
		return nil
	}

	// Mean traffic of all pods together
	meanTraffic := float64(totalTraffic) / float64(activePodsCount)

	anomalousPods := make([]string, 0)
	for podName, bytes := range traffic {
		if bytes < d.config.MinTrafficThreshold {
			continue
		}

		stats, ok := d.podStats[podName]
		if !ok {
			stats = &PodStats{
				readings:   make([]int64, d.config.WindowSize),
				lastUpdate: currentTime,
			}
			d.podStats[podName] = stats
		}

		d.updatePodStats(stats, bytes)

		isAnomalous := d.isAnomalous(stats, bytes, meanTraffic)

		if isAnomalous {
			stats.anomalyCount++
			if stats.anomalyCount >= d.config.ConsecutiveAnomalies {
				anomalousPods = append(anomalousPods, podName)
			}
		} else {
			stats.anomalyCount = 0
		}
	}

	return anomalousPods
}

func (d *Detector) updatePodStats(stats *PodStats, bytes int64) {
	if stats.count >= d.config.WindowSize {
		oldBytes := stats.readings[stats.position]
		stats.sum -= oldBytes
		stats.sumSq -= float64(oldBytes * oldBytes)
		stats.count--
	}

	stats.readings[stats.position] = bytes
	stats.sum += bytes
	stats.sumSq += float64(bytes * bytes)
	stats.count++

	stats.position = (stats.position + 1) % d.config.WindowSize
}

func (d *Detector) isAnomalous(stats *PodStats, bytes int64, clusterMean float64) bool {
	if stats.count < d.config.WindowSize/2 {
		return false
	}

	mean := float64(stats.sum) / float64(stats.count)
	variance := (stats.sumSq / float64(stats.count)) - (mean * mean)
	stdDev := float64(1)
	if variance > 0 {
		stdDev = math.Sqrt(variance)
	}

	zScore := math.Abs(float64(bytes)-mean) / stdDev
	if zScore > d.config.StdDevThreshold {
		return true
	}

	if float64(bytes) > clusterMean*2 {
		return true
	}

	return false
}

// generateSampleTraffic generates sample traffic data for testing
func generateSampleTraffic(podCount int, timestamp int) map[string]int64 {
	traffic := make(map[string]int64)

	// Generate normal traffic pattern for most pods
	for i := 0; i < podCount; i++ {
		podName := fmt.Sprintf("pod-%d", i)
		baseTraffic := int64(1000 + rand.Intn(500))

		// Add some random variation
		variation := int64(rand.NormFloat64() * 100)
		traffic[podName] = baseTraffic + variation
	}

	// Simulate an anomaly in one pod every 5 seconds
	if timestamp%5 == 0 {
		anomalousPod := fmt.Sprintf("pod-%d", rand.Intn(podCount))
		// Make the spike much more pronounced (20x normal traffic)
		traffic[anomalousPod] = traffic[anomalousPod] * 20
		fmt.Printf("\n[DEBUG] Generating spike for %s at timestamp %d\n", anomalousPod, timestamp)
	}

	return traffic
}

func main() {
	// Set random seed for reproducibility
	rand.Seed(time.Now().UnixNano())

	// Configure the detector with more sensitive parameters
	config := Config{
		WindowSize:           10,  // 10 seconds of history (shorter window to detect spikes faster)
		StdDevThreshold:      2.5, // Lower threshold (2.5 standard deviations)
		ConsecutiveAnomalies: 1,   // Detect single anomalies
		MinTrafficThreshold:  100, // Minimum bytes to consider
	}

	detector := NewDetector(config)

	// Simulation parameters
	podCount := 5
	simulationSeconds := 30

	fmt.Println("Starting traffic anomaly detection simulation...")
	fmt.Printf("Monitoring %d pods for %d seconds\n", podCount, simulationSeconds)
	fmt.Printf("Traffic spikes will be generated every 5 seconds\n")
	fmt.Println("============================================")

	// Main simulation loop
	for t := 0; t < simulationSeconds; t++ {
		// Generate sample traffic data
		traffic := generateSampleTraffic(podCount, t)

		// Process traffic and detect anomalies
		anomalous := detector.ProcessTraffic(traffic)

		// Print current traffic and any anomalies
		fmt.Printf("\nTimestamp: %d\n", t)
		fmt.Println("Current traffic (bytes):")

		// Sort and print pod names for consistent output
		podNames := make([]string, 0, len(traffic))
		for pod := range traffic {
			podNames = append(podNames, pod)
		}

		// Print traffic data
		for _, pod := range podNames {
			bytes := traffic[pod]
			fmt.Printf("  %-6s: %8d", pod, bytes)
			if contains(anomalous, pod) {
				fmt.Print(" 🚨 ANOMALY DETECTED!")
			}
			fmt.Println()
		}

		if len(anomalous) > 0 {
			fmt.Printf("\n⚠️  Detected %d anomalous pods at timestamp %d\n", len(anomalous), t)
		}

		time.Sleep(time.Second)
	}
}

// contains checks if a string is present in a slice
func contains(slice []string, str string) bool {
	for _, v := range slice {
		if v == str {
			return true
		}
	}
	return false
}
