package pieceurls

import "net/http"

const (
	defaultFilecoinToolsAPI  = "https://api.filecoin.tools/api"
	defaultCIDContactBaseURL = "https://cid.contact"
	defaultSearchPageLimit   = 100
	defaultProviderParallel  = 8
	defaultProbeParallel     = 16
)

// Client discovers SP HTTP bases and probes /piece endpoints.
type Client struct {
	HTTP *http.Client

	// LotusRPC is used for Filecoin.StateMinerInfo (same chain as FVM / payments RPC).
	LotusRPC string

	// ProbeClient, when set, is sent as ?client=<addr> on a second probe attempt
	// after an anonymous GET returns 403 (private deal).
	ProbeClient string

	FilecoinToolsAPI    string
	CIDContactBaseURL   string
	SearchPageLimit     int
	ProviderParallelism int
	ProbeParallelism    int
}

// Option configures a Client.
type Option func(*Client)

// WithLotusRPC sets the Lotus JSON-RPC URL for miner info lookups.
func WithLotusRPC(url string) Option {
	return func(c *Client) {
		c.LotusRPC = url
	}
}

// WithFilecoinToolsAPI overrides the filecoin.tools search API base URL.
func WithFilecoinToolsAPI(api string) Option {
	return func(c *Client) {
		c.FilecoinToolsAPI = api
	}
}

// WithCIDContactBaseURL overrides the cid.contact API base URL.
func WithCIDContactBaseURL(base string) Option {
	return func(c *Client) {
		c.CIDContactBaseURL = base
	}
}

// NewClient returns a piece discovery/probe client. httpClient must be non-nil.
func NewClient(httpClient *http.Client, opts ...Option) *Client {
	c := &Client{
		HTTP:                httpClient,
		FilecoinToolsAPI:    defaultFilecoinToolsAPI,
		CIDContactBaseURL:   defaultCIDContactBaseURL,
		SearchPageLimit:     defaultSearchPageLimit,
		ProviderParallelism: defaultProviderParallel,
		ProbeParallelism:    defaultProbeParallel,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}
