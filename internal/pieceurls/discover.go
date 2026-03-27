package pieceurls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

const (
	filecoinToolsAPI  = "https://api.filecoin.tools/api"
	cidContactBaseURL = "https://cid.contact"
	searchPageLimit   = 100
	parallelProviders = 8
)

// DiscoverPieceHTTPBases returns unique SP HTTP bases that may serve /piece/<pieceCID>,
// following the same steps as DUV cid-all-sp-piece-urls.sh (filecoin.tools search → providers → cid.contact / Lotus).
// lotusRPC is used for Filecoin.StateMinerInfo (same chain as your FVM / payments RPC).
func DiscoverPieceHTTPBases(ctx context.Context, cli *http.Client, pieceCID, lotusRPC string) ([]*url.URL, error) {
	if strings.TrimSpace(pieceCID) == "" {
		return nil, fmt.Errorf("empty piece CID")
	}
	providers, err := searchAllProviderIDs(ctx, cli, pieceCID)
	if err != nil {
		return nil, err
	}
	if len(providers) == 0 {
		return nil, nil
	}

	sem := make(chan struct{}, parallelProviders)
	var mu sync.Mutex
	baseStrs := map[string]struct{}{}

	var g errgroup.Group
	for _, pid := range providers {
		pid := pid
		g.Go(func() error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			bases, err := resolveProviderHTTPBases(ctx, cli, pid, lotusRPC)
			if err != nil {
				// Best-effort per provider (Lotus / cid.contact flakes).
				return nil
			}
			mu.Lock()
			for _, b := range bases {
				b = strings.TrimRight(strings.TrimSpace(b), "/")
				if b == "" {
					continue
				}
				baseStrs[b] = struct{}{}
			}
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait()

	if len(baseStrs) == 0 {
		return nil, nil
	}
	sorted := make([]string, 0, len(baseStrs))
	for b := range baseStrs {
		sorted = append(sorted, b)
	}
	sort.Strings(sorted)

	out := make([]*url.URL, 0, len(sorted))
	for _, s := range sorted {
		u, err := url.Parse(s)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		u.Path = ""
		u.RawQuery = ""
		u.Fragment = ""
		out = append(out, u)
	}
	return out, nil
}

func searchAllProviderIDs(ctx context.Context, cli *http.Client, pieceCID string) ([]string, error) {
	seen := map[string]struct{}{}
	var order []string
	limit := searchPageLimit
	api := strings.TrimRight(filecoinToolsAPI, "/")

	for page := 1; ; page++ {
		u, err := url.Parse(api + "/search")
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("page", fmt.Sprintf("%d", page))
		q.Set("limit", fmt.Sprintf("%d", limit))
		q.Set("filter", pieceCID)
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "*/*")

		res, err := cli.Do(req)
		if err != nil {
			return nil, fmt.Errorf("filecoin.tools search page %d: %w", page, err)
		}
		body, err := io.ReadAll(io.LimitReader(res.Body, 1<<24))
		res.Body.Close()
		if err != nil {
			return nil, err
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return nil, fmt.Errorf("filecoin.tools search page %d: %s", page, res.Status)
		}

		var payload struct {
			Data []struct {
				ProviderID      string `json:"providerId"`
				ProviderIDSnake string `json:"provider_id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			return nil, fmt.Errorf("filecoin.tools search page %d: parse json: %w", page, err)
		}
		if len(payload.Data) == 0 {
			break
		}
		for _, row := range payload.Data {
			id := strings.TrimSpace(row.ProviderID)
			if id == "" {
				id = strings.TrimSpace(row.ProviderIDSnake)
			}
			id = normalizeProviderID(id)
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			order = append(order, id)
		}
		if len(payload.Data) < limit {
			break
		}
	}
	return order, nil
}

func normalizeProviderID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "f0")
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	if s == "" {
		return ""
	}
	return "f0" + s
}

func resolveProviderHTTPBases(ctx context.Context, cli *http.Client, providerID, lotusRPC string) ([]string, error) {
	minfo, err := lotusStateMinerInfo(ctx, cli, lotusRPC, providerID)
	if err != nil {
		return nil, err
	}
	var endpoints []string
	if minfo != nil && strings.TrimSpace(minfo.PeerID) != "" {
		addrs, err := cidContactAddrs(ctx, cli, cidContactBaseURL, minfo.PeerID)
		if err == nil {
			for _, a := range addrs {
				if b := HTTPBaseFromMultiaddrString(a); b != "" {
					endpoints = append(endpoints, strings.TrimRight(b, "/"))
				}
			}
		}
	}
	if len(endpoints) == 0 && minfo != nil {
		endpoints = append(endpoints, HTTPBasesFromLotusMultiaddrsBase64(minfo.Multiaddrs)...)
	}
	return endpoints, nil
}

type minerInfoResult struct {
	PeerID     string   `json:"PeerId"`
	Multiaddrs []string `json:"Multiaddrs"`
}

func lotusStateMinerInfo(ctx context.Context, cli *http.Client, lotusRPC, providerID string) (*minerInfoResult, error) {
	rpc := strings.TrimSpace(lotusRPC)
	if rpc == "" {
		return nil, fmt.Errorf("empty lotus RPC URL")
	}
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"Filecoin.StateMinerInfo","params":["%s",null]}`, providerID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpc, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Result *minerInfoResult `json:"result"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		return nil, err
	}
	return wrap.Result, nil
}

func cidContactAddrs(ctx context.Context, cli *http.Client, cidContactBase, peerID string) ([]string, error) {
	base := strings.TrimRight(strings.TrimSpace(cidContactBase), "/")
	u := base + "/providers/" + strings.TrimPrefix(strings.TrimSpace(peerID), "/")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	res, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 1<<22))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("cid.contact %s: %s", u, res.Status)
	}
	var root interface{}
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, err
	}
	var out []string
	walkCollectAddrs(root, &out)
	return out, nil
}

func walkCollectAddrs(v interface{}, out *[]string) {
	switch x := v.(type) {
	case map[string]interface{}:
		if raw, ok := x["Addrs"]; ok {
			appendAddrsSlice(raw, out)
		}
		for _, v2 := range x {
			walkCollectAddrs(v2, out)
		}
	case []interface{}:
		for _, v2 := range x {
			walkCollectAddrs(v2, out)
		}
	}
}

func appendAddrsSlice(raw interface{}, out *[]string) {
	arr, ok := raw.([]interface{})
	if !ok {
		return
	}
	for _, e := range arr {
		s, ok := e.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			*out = append(*out, s)
		}
	}
}
