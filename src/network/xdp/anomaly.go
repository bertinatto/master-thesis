package main

import (
	"math"
	"time"
)

type Config struct {
	WindowSize           int
	StdDevThreshold      float64
	ConsecutiveAnomalies int
	MinTrafficThreshold  int64
}

type PodStats struct {
	readings     []int64 // Store delta values, not raw cumulative values
	position     int
	sum          int64
	sumSq        float64
	count        int
	anomalyCount int
	lastUpdate   time.Time
	lastReading  int64 // Store the last cumulative reading to calculate delta
	initialized  bool  // Track if we've received the first reading
}

type Detector struct {
	config    Config
	podStats  map[string]*PodStats
	timestamp time.Time
}

func NewDetector(config Config) *Detector {
	return &Detector{
		config:   config,
		podStats: make(map[string]*PodStats),
	}
}

// ProcessTraffic now handles cumulative measurements
func (d *Detector) ProcessTraffic(traffic map[Pod]int64) []string {
	currentTime := time.Now()

	// Calculate deltas and cluster statistics
	deltas := make(map[string]int64)

	// First pass: calculate deltas
	for pod, cumBytes := range traffic {
		stats, exists := d.podStats[pod.Name]
		if !exists {
			stats = &PodStats{
				readings:   make([]int64, d.config.WindowSize),
				lastUpdate: currentTime,
			}
			d.podStats[pod.Name] = stats
		}

		// Calculate delta if we have a previous reading
		var delta int64
		if stats.initialized {
			delta = cumBytes - stats.lastReading
			if delta < 0 {
				// Handle counter reset or overflow
				delta = cumBytes
			}
		} else {
			// First reading, can't calculate meaningful delta
			stats.initialized = true
			delta = 0
		}
		stats.lastReading = cumBytes

		if delta >= d.config.MinTrafficThreshold {
			deltas[pod.Name] = delta
		}
	}

	// Second pass: update the pod stats and detect anomalies using deltas
	anomalousPods := make([]string, 0)
	for podName, delta := range deltas {
		// Update the pod stats BEFORE checking if this delta is anomalous
		stats := d.podStats[podName]
		d.updatePodStats(stats, delta)

		isAnomalous := d.isAnomalous(stats, delta)
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

func (d *Detector) updatePodStats(stats *PodStats, deltaBytes int64) {
	// If buffer is full, remove oldest reading
	if stats.count >= d.config.WindowSize {
		oldDelta := stats.readings[stats.position]
		stats.sum -= oldDelta
		stats.sumSq -= float64(oldDelta * oldDelta)
		stats.count--
	}

	// Add new delta reading
	stats.readings[stats.position] = deltaBytes
	stats.sum += deltaBytes
	stats.sumSq += float64(deltaBytes * deltaBytes)
	stats.count++

	// Move position in circular buffer
	stats.position = (stats.position + 1) % d.config.WindowSize
}

func (d *Detector) isAnomalous(stats *PodStats, deltaBytes int64) bool {
	// Need at least half a window of delta values before making decisions
	if stats.count < d.config.WindowSize/2 {
		return false
	}

	// Calculate mean and standard deviation of deltas
	mean := float64(stats.sum) / float64(stats.count)
	variance := (stats.sumSq / float64(stats.count)) - (mean * mean)
	stdDev := float64(1)
	if variance > 0 {
		stdDev = math.Sqrt(variance)
	}

	// Compare current delta with historical patterns
	zScore := math.Abs(float64(deltaBytes)-mean) / stdDev
	return zScore > d.config.StdDevThreshold
}
