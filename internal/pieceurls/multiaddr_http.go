package pieceurls

import (
	"encoding/base64"
	"regexp"
	"strings"

	ma "github.com/multiformats/go-multiaddr"
)

var (
	reIP4HTTP  = regexp.MustCompile(`^/ip4/([^/]+)/tcp/([0-9]+)/http/?$`)
	reIP4HTTPS = regexp.MustCompile(`^/ip4/([^/]+)/tcp/([0-9]+)/https/?$`)
	reDNSHTTP  = regexp.MustCompile(`^/dns4/([^/]+)/tcp/([0-9]+)/http/?$`)
	reDNSHTTPS = regexp.MustCompile(`^/dns4/([^/]+)/tcp/([0-9]+)/https/?$`)
)

// HTTPBaseFromMultiaddrString maps a multiaddr string to http(s)://host:port, same rules as lib_piece_endpoints.sh.
func HTTPBaseFromMultiaddrString(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if m := reIP4HTTP.FindStringSubmatch(addr); len(m) == 3 {
		return "http://" + m[1] + ":" + m[2]
	}
	if m := reIP4HTTPS.FindStringSubmatch(addr); len(m) == 3 {
		return "https://" + m[1] + ":" + m[2]
	}
	if m := reDNSHTTP.FindStringSubmatch(addr); len(m) == 3 {
		return "http://" + m[1] + ":" + m[2]
	}
	if m := reDNSHTTPS.FindStringSubmatch(addr); len(m) == 3 {
		return "https://" + m[1] + ":" + m[2]
	}
	return ""
}

// HTTPBasesFromLotusMultiaddrsBase64 decodes Lotus StateMinerInfo.Multiaddrs (base64) and extracts HTTP bases.
func HTTPBasesFromLotusMultiaddrsBase64(lines []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			continue
		}
		m, err := ma.NewMultiaddrBytes(raw)
		if err != nil {
			continue
		}
		base := HTTPBaseFromMultiaddrString(m.String())
		if base == "" {
			continue
		}
		base = strings.TrimRight(base, "/")
		if _, ok := seen[base]; ok {
			continue
		}
		seen[base] = struct{}{}
		out = append(out, base)
	}
	return out
}
