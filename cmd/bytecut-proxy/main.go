// Command bytecut-proxy is a chaos reverse proxy for Curio piece HTTP.
// It forwards requests upstream, then hard-resets the client connection after
// drop-bytes of response body (default 0.5 MiB). HEAD responses are never cut.
//
// Used between sp-proxy and Curio so retrieval-client Range resume is exercised.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:22311", "listen address")
	upstream := flag.String("upstream", "http://127.0.0.1:22310", "upstream base URL")
	dropBytes := flag.Int64("drop-bytes", 1<<19, "reset client connection after this many response body bytes")
	flag.Parse()

	u, err := url.Parse(*upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		fmt.Fprintf(os.Stderr, "invalid --upstream %q\n", *upstream)
		os.Exit(2)
	}
	if *dropBytes <= 0 {
		fmt.Fprintf(os.Stderr, "--drop-bytes must be > 0\n")
		os.Exit(2)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.FlushInterval = 100 * time.Millisecond

	h := &cutHandler{proxy: proxy, dropBytes: *dropBytes, upstream: u}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "bytecut-proxy listening on %s → %s (drop after %d bytes)\n", *listen, u.String(), *dropBytes)
	if err := http.Serve(ln, h); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

type cutHandler struct {
	proxy     *httputil.ReverseProxy
	dropBytes int64
	upstream  *url.URL
}

func (h *cutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// HEAD must stay intact (quotes / sizing). Only cut streaming GET bodies.
	if r.Method == http.MethodHead {
		h.proxy.ServeHTTP(w, r)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.URL.Scheme = h.upstream.Scheme
	outReq.URL.Host = h.upstream.Host
	outReq.RequestURI = ""
	if outReq.Host == "" {
		outReq.Host = h.upstream.Host
	}

	res, err := http.DefaultTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	if err := writeStatusAndHeaders(bufrw, res); err != nil {
		resetTCP(conn)
		return
	}
	if err := bufrw.Flush(); err != nil {
		resetTCP(conn)
		return
	}

	n, copyErr := io.CopyN(bufrw, res.Body, h.dropBytes)
	_ = bufrw.Flush()
	if copyErr == nil && n >= h.dropBytes {
		// Drop budget exhausted: RST so the client cannot block on Content-Length.
		resetTCP(conn)
		return
	}
	if copyErr != nil && copyErr != io.EOF {
		resetTCP(conn)
		return
	}
	// Upstream body finished under the limit (e.g. final Range): clean close via defer.
}

func writeStatusAndHeaders(bw *bufio.ReadWriter, res *http.Response) error {
	status := res.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", res.StatusCode, http.StatusText(res.StatusCode))
	}
	if _, err := fmt.Fprintf(bw, "%s %s\r\n", res.Proto, status); err != nil {
		return err
	}
	if err := res.Header.Write(bw); err != nil {
		return err
	}
	_, err := io.WriteString(bw, "\r\n")
	return err
}

func resetTCP(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = conn.Close()
}
