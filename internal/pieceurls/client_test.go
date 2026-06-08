package pieceurls

import (
	"context"
	"net/http"
	"testing"
)

func TestNewClientRequiresHTTP(t *testing.T) {
	if _, err := NewClient(nil).DiscoverPieceHTTPBases(context.Background(), "bafy1"); err == nil {
		t.Fatal("expected error for nil HTTP client")
	}
	if _, err := NewClient(nil).SelectBestPieceSource(context.Background(), "bafy", nil, nil, nil); err == nil {
		t.Fatal("expected error for nil HTTP client on select")
	}
}

func TestClientOptions(t *testing.T) {
	c := NewClient(&http.Client{},
		WithLotusRPC("http://lotus"),
		WithFilecoinToolsAPI("http://tools/api"),
		WithCIDContactBaseURL("http://cid"),
	)
	if c.LotusRPC != "http://lotus" || c.FilecoinToolsAPI != "http://tools/api" || c.CIDContactBaseURL != "http://cid" {
		t.Fatalf("opts: lotus=%q tools=%q cid=%q", c.LotusRPC, c.FilecoinToolsAPI, c.CIDContactBaseURL)
	}
}

func TestNewClientEmptyCID(t *testing.T) {
	c := NewClient(&http.Client{}, WithLotusRPC("http://127.0.0.1:1234"))
	if _, err := c.DiscoverPieceHTTPBases(context.Background(), "  "); err == nil {
		t.Fatal("expected empty CID error")
	}
}
