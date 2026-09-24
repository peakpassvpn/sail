// loadgen drives traffic through a SOCKS5 proxy towards a local sink server.
//
//	loadgen sink -listen 127.0.0.1:9000
//	loadgen throughput -proxy 127.0.0.1:1081 -target 127.0.0.1:9000 -streams 8 -bytes 268435456 -dir down
//	loadgen latency -proxy 127.0.0.1:1081 -target 127.0.0.1:9000 -n 2000
//	loadgen concurrent -proxy 127.0.0.1:1081 -target 127.0.0.1:9000 -conns 2000 -hold 5s
//
// Every client mode prints a single JSON object on stdout.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cmdDown = 'D' // server sends N bytes
	cmdUp   = 'U' // client sends N bytes, server replies with 1 byte when done
	cmdEcho = 'E' // server echoes until EOF
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: loadgen sink|throughput|latency|concurrent [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:9000", "sink listen address")
	proxy := fs.String("proxy", "127.0.0.1:1081", "SOCKS5 proxy address")
	target := fs.String("target", "127.0.0.1:9000", "sink address, as seen by the proxy")
	streams := fs.Int("streams", 8, "parallel streams (throughput)")
	size := fs.Int64("bytes", 256<<20, "bytes per stream (throughput)")
	dir := fs.String("dir", "down", "down|up (throughput)")
	n := fs.Int("n", 2000, "sequential connections (latency)")
	conns := fs.Int("conns", 2000, "simultaneous connections (concurrent)")
	hold := fs.Duration("hold", 5*time.Second, "how long connections stay open (concurrent)")
	fs.Parse(os.Args[2:])

	var res any
	var err error
	switch os.Args[1] {
	case "sink":
		err = runSink(*listen)
	case "throughput":
		res, err = runThroughput(*proxy, *target, *streams, *size, *dir)
	case "latency":
		res, err = runLatency(*proxy, *target, *n)
	case "concurrent":
		res, err = runConcurrent(*proxy, *target, *conns, *hold)
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(res)
}

// ---- sink ----

func runSink(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go serveSink(c)
	}
}

func serveSink(c net.Conn) {
	defer c.Close()
	var hdr [9]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return
	}
	n := int64(binary.BigEndian.Uint64(hdr[1:]))
	switch hdr[0] {
	case cmdDown:
		buf := make([]byte, 64<<10)
		for n > 0 {
			k := int64(len(buf))
			if n < k {
				k = n
			}
			w, err := c.Write(buf[:k])
			if err != nil {
				return
			}
			n -= int64(w)
		}
	case cmdUp:
		if _, err := io.CopyN(io.Discard, c, n); err != nil {
			return
		}
		c.Write([]byte{1})
	case cmdEcho:
		io.Copy(c, c)
	}
}

// ---- SOCKS5 ----

func dialSocks(proxy, target string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, errors.New("target must be an IPv4 address")
	}
	c, err := net.DialTimeout("tcp", proxy, 10*time.Second)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	req := []byte{5, 1, 0, 5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	// method selection (2 bytes) + connect reply for an IPv4 bind address (10 bytes)
	var resp [12]byte
	if _, err := io.ReadFull(c, resp[:]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks handshake: %w", err)
	}
	if resp[1] != 0 || resp[3] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks rejected: method=%d rep=%d", resp[1], resp[3])
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

func header(cmd byte, n int64) []byte {
	h := make([]byte, 9)
	h[0] = cmd
	binary.BigEndian.PutUint64(h[1:], uint64(n))
	return h
}

// ---- throughput ----

type throughputResult struct {
	Streams  int     `json:"streams"`
	Bytes    int64   `json:"bytes"`
	Seconds  float64 `json:"seconds"`
	MBps     float64 `json:"mbps"`
	Failures int     `json:"failures"`
}

func runThroughput(proxy, target string, streams int, size int64, dir string) (any, error) {
	var total atomic.Int64
	var failures atomic.Int32
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := oneStream(proxy, target, size, dir)
			total.Add(n)
			if err != nil {
				failures.Add(1)
				fmt.Fprintln(os.Stderr, "stream:", err)
			}
		}()
	}
	wg.Wait()
	secs := time.Since(start).Seconds()
	return throughputResult{
		Streams:  streams,
		Bytes:    total.Load(),
		Seconds:  secs,
		MBps:     float64(total.Load()) / secs / 1e6,
		Failures: int(failures.Load()),
	}, nil
}

func oneStream(proxy, target string, size int64, dir string) (int64, error) {
	c, err := dialSocks(proxy, target)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	if dir == "up" {
		if _, err := c.Write(header(cmdUp, size)); err != nil {
			return 0, err
		}
		buf := make([]byte, 64<<10)
		var sent int64
		for sent < size {
			k := int64(len(buf))
			if size-sent < k {
				k = size - sent
			}
			w, err := c.Write(buf[:k])
			sent += int64(w)
			if err != nil {
				return sent, err
			}
		}
		var ack [1]byte
		_, err := io.ReadFull(c, ack[:])
		return sent, err
	}
	if _, err := c.Write(header(cmdDown, size)); err != nil {
		return 0, err
	}
	n, err := io.CopyN(io.Discard, c, size)
	return n, err
}

// ---- latency ----

type latencyResult struct {
	N        int     `json:"n"`
	Failures int     `json:"failures"`
	P50ms    float64 `json:"p50_ms"`
	P90ms    float64 `json:"p90_ms"`
	P99ms    float64 `json:"p99_ms"`
	MaxMs    float64 `json:"max_ms"`
	// Round trip of a 64-byte message on an already established connection.
	RttP50ms float64 `json:"rtt_p50_ms"`
	RttP99ms float64 `json:"rtt_p99_ms"`
}

// runLatency measures, one connection at a time, the time from dialing the
// proxy until the first echoed byte comes back (setup cost of a new
// connection), then the steady-state round trip on one long-lived connection.
func runLatency(proxy, target string, n int) (any, error) {
	setup := make([]time.Duration, 0, n)
	failures := 0
	msg := make([]byte, 64)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		c, err := dialSocks(proxy, target)
		if err != nil {
			failures++
			continue
		}
		if err := echoOnce(c, append(header(cmdEcho, 0), msg...), len(msg)); err != nil {
			failures++
			c.Close()
			continue
		}
		setup = append(setup, time.Since(t0))
		c.Close()
	}

	c, err := dialSocks(proxy, target)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if _, err := c.Write(header(cmdEcho, 0)); err != nil {
		return nil, err
	}
	rtt := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if err := echoOnce(c, msg, len(msg)); err != nil {
			return nil, err
		}
		rtt = append(rtt, time.Since(t0))
	}

	sp, rp := percentiles(setup), percentiles(rtt)
	return latencyResult{
		N: n, Failures: failures,
		P50ms: sp(0.50), P90ms: sp(0.90), P99ms: sp(0.99), MaxMs: sp(1),
		RttP50ms: rp(0.50), RttP99ms: rp(0.99),
	}, nil
}

func echoOnce(c net.Conn, send []byte, want int) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write(send); err != nil {
		return err
	}
	buf := make([]byte, want)
	_, err := io.ReadFull(c, buf)
	return err
}

func percentiles(ds []time.Duration) func(float64) float64 {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
	return func(p float64) float64 {
		if len(ds) == 0 {
			return 0
		}
		i := int(p*float64(len(ds))) - 1
		if i < 0 {
			i = 0
		}
		return float64(ds[i].Microseconds()) / 1000
	}
}

// ---- concurrent ----

type concurrentResult struct {
	Conns       int     `json:"conns"`
	Established int     `json:"established"`
	Failures    int     `json:"failures"`
	OpenSeconds float64 `json:"open_seconds"`
}

// runConcurrent opens conns echo connections, verifies each one round-trips a
// byte, keeps them all open for hold (the harness samples memory meanwhile),
// then closes them.
func runConcurrent(proxy, target string, conns int, hold time.Duration) (any, error) {
	var mu sync.Mutex
	open := make([]net.Conn, 0, conns)
	failures := 0
	sem := make(chan struct{}, 200) // cap in-flight handshakes
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < conns; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := dialSocks(proxy, target)
			if err == nil {
				err = echoOnce(c, append(header(cmdEcho, 0), 'x'), 1)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if failures <= 5 {
					fmt.Fprintln(os.Stderr, "conn:", err)
				}
				if c != nil {
					c.Close()
				}
				return
			}
			open = append(open, c)
		}()
	}
	wg.Wait()
	openSecs := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "HOLDING %d\n", len(open))
	time.Sleep(hold)
	for _, c := range open {
		c.Close()
	}
	return concurrentResult{Conns: conns, Established: len(open), Failures: failures, OpenSeconds: openSecs}, nil
}
