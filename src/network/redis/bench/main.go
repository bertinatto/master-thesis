package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/go-redis/redis/v8"
)

func main() {
	prefix := flag.String("prefix", "", "Prefix for the output file")
	host := flag.String("host", "", "Host of the redis server")
	port := flag.Int("port", 6379, "Port number of the redis server")
	flag.Parse()

	// Create a new Redis client.
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", *host, *port),
		Password: "", // no password set
		DB:       0,  // use default DB
	})

	// Function to generate random string data for SET operations.
	generateRandomData := func(length int) string {
		const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, length)
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		return string(b)
	}

	// Open CSV files for writing latencies.
	fd, err := os.Create(fmt.Sprintf("%s_latencies.csv", *prefix))
	if err != nil {
		panic(err)
	}
	defer fd.Close()

	csvWriter := csv.NewWriter(fd)
	defer csvWriter.Flush()

	// Write headers to the CSV files.
	if err := csvWriter.Write([]string{"request", "operation", "latency_us"}); err != nil {
		panic(err)
	}

	// Perform 100,000 SET followed by GET operations.
	pid := os.Getpid()
	ctx := context.Background()
	for i := 0; i < 100000; i++ {
		key := fmt.Sprintf("key_%d_%d", pid, i)
		originalValue := generateRandomData(1000) // Generate random data for the value.

		// Measure the latency of each SET operation.
		start := time.Now()
		err := rdb.Set(ctx, key, originalValue, 0).Err()
		setLatency := time.Since(start).Microseconds()

		if err != nil {
			fmt.Printf("Error on SET: %v\n", err)
			continue
		}

		// Write the SET latency to the CSV file.
		if err := csvWriter.Write([]string{fmt.Sprintf("%d", i+1), "SET", fmt.Sprintf("%d", setLatency)}); err != nil {
			panic(err)
		}

	}
	csvWriter.Flush()

	for i := 0; i < 100000; i++ {
		key := fmt.Sprintf("key_%d_%d", pid, i)

		// Measure the latency of each GET operation.
		start := time.Now()
		_, err := rdb.Get(ctx, key).Result()
		getLatency := time.Since(start).Microseconds()

		if err != nil {
			panic(fmt.Sprintf("Error on GET: %v\n", err))
		}

		// Write the GET latency to the CSV file.
		if err := csvWriter.Write([]string{fmt.Sprintf("%d", i+1), "GET", fmt.Sprintf("%d", getLatency)}); err != nil {
			panic(err)
		}
	}

	fmt.Println("Operation completed, latencies written to set_latencies.csv and get_latencies.csv")
}
