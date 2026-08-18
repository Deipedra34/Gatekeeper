// Command loadtest fires concurrent HTTP requests at a running
// Gatekeeper instance (or honestly any HTTP server) and reports how many
// got through, how many got rate limited, and what the latency looked
// like. The point is just to make the rate limiter's behavior under load
// easy to see and reproduce — example output is in the README.
//
// Usage:
//
//	go run ./scripts/loadtest -target http://localhost:8080/api/ping -api-key free-key -requests 200 -concurrency 20
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

type result struct {
	status  int
	latency time.Duration
	err     error
}

func main() {
	target := flag.String("target", "http://localhost:8080/api/ping", "URL to hit")
	apiKey := flag.String("api-key", "", "value to send in the X-API-Key header (blank = omit)")
	requests := flag.Int("requests", 200, "total number of requests to send")
	concurrency := flag.Int("concurrency", 20, "number of concurrent workers")
	flag.Parse()

	if *requests <= 0 || *concurrency <= 0 {
		fmt.Fprintln(os.Stderr, "loadtest: -requests and -concurrency must be positive")
		os.Exit(1)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	jobs := make(chan int, *requests)
	for i := 0; i < *requests; i++ {
		jobs <- i
	}
	close(jobs)

	results := make(chan result, *requests)
	var wg sync.WaitGroup
	wg.Add(*concurrency)
	for w := 0; w < *concurrency; w++ {
		go func() {
			defer wg.Done()
			for range jobs {
				results <- doRequest(client, *target, *apiKey)
			}
		}()
	}

	start := time.Now()
	wg.Wait()
	close(results)
	totalElapsed := time.Since(start)

	summarize(results, *requests, *concurrency, totalElapsed)
}

func doRequest(client *http.Client, target, apiKey string) result {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return result{err: err}
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	start := time.Now()
	resp, err := client.Do(req)
	latency := time.Since(start)
	if err != nil {
		return result{latency: latency, err: err}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	return result{status: resp.StatusCode, latency: latency}
}

func summarize(results <-chan result, total, concurrency int, elapsed time.Duration) {
	var allowed, rejected, failed int
	latencies := make([]time.Duration, 0, total)

	for r := range results {
		switch {
		case r.err != nil:
			failed++
		case r.status == http.StatusTooManyRequests:
			rejected++
			latencies = append(latencies, r.latency)
		case r.status >= 200 && r.status < 300:
			allowed++
			latencies = append(latencies, r.latency)
		default:
			failed++
			latencies = append(latencies, r.latency)
		}
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Printf("Gatekeeper load test\n")
	fmt.Printf("=====================\n")
	fmt.Printf("requests:      %d (concurrency %d)\n", total, concurrency)
	fmt.Printf("wall time:     %s (%.1f req/s)\n", elapsed.Round(time.Millisecond), float64(total)/elapsed.Seconds())
	fmt.Printf("allowed (2xx): %d\n", allowed)
	fmt.Printf("rejected (429):%d\n", rejected)
	fmt.Printf("failed:        %d\n", failed)
	fmt.Println()
	fmt.Printf("latency  min=%s  p50=%s  p95=%s  p99=%s  max=%s\n",
		percentile(latencies, 0), percentile(latencies, 50),
		percentile(latencies, 95), percentile(latencies, 99),
		percentile(latencies, 100))
}

func percentile(sorted []time.Duration, p int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := p * (len(sorted) - 1) / 100
	return sorted[idx].Round(time.Microsecond)
}
