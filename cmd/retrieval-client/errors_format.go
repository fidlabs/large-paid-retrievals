package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

type pieceDownloadFailure struct {
	idx int
	cid string
	err error
}

func newDownloadFailuresError(items []challengeItem, failures []pieceDownloadFailure) error {
	var b strings.Builder
	fmt.Fprintf(&b, "download failed for %d piece(s):", len(failures))
	sort.Slice(failures, func(i, j int) bool { return failures[i].idx < failures[j].idx })
	for n, f := range failures {
		fmt.Fprintf(&b, "\n\n  %d. %s", n+1, shortCID(f.cid))
		for _, line := range formatDownloadErrorLines(f.cid, f.err) {
			fmt.Fprintf(&b, "\n     %s", line)
		}
	}
	return errors.New(strings.TrimSuffix(b.String(), "\n"))
}

func formatDownloadErrorLines(cid string, err error) []string {
	if err == nil {
		return []string{"unknown error"}
	}
	msg := strings.TrimSpace(err.Error())
	msg = stripDownloadErrorPrefix(cid, msg)

	if pd, prefix, ok := parseProblemFromText(msg); ok {
		lines := make([]string, 0, 2)
		head := strings.TrimSpace(prefix)
		if pd.Title != "" {
			if head != "" {
				head += " — " + pd.Title
			} else {
				head = pd.Title
			}
		}
		if head != "" {
			lines = append(lines, head)
		}
		if pd.Detail != "" {
			lines = append(lines, pd.Detail)
		}
		if len(lines) > 0 {
			return lines
		}
	}

	if msg == "" {
		return []string{"unknown error"}
	}
	return []string{msg}
}

func stripDownloadErrorPrefix(cid, msg string) string {
	for _, prefix := range []string{
		"download " + cid + " failed: ",
		"download " + shortCID(cid) + " failed: ",
	} {
		if strings.HasPrefix(msg, prefix) {
			return strings.TrimSpace(msg[len(prefix):])
		}
	}
	return msg
}

func parseProblemFromText(msg string) (problemDetails, string, bool) {
	i := strings.Index(msg, "{")
	if i < 0 {
		return problemDetails{}, "", false
	}
	prefix := strings.TrimSpace(msg[:i])
	var pd problemDetails
	if err := json.Unmarshal([]byte(msg[i:]), &pd); err != nil || pd.Type == "" {
		return problemDetails{}, "", false
	}
	return pd, prefix, true
}

func parseProblemJSON(raw string) (problemDetails, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return problemDetails{}, false
	}
	var pd problemDetails
	if err := json.Unmarshal([]byte(raw), &pd); err != nil || pd.Type == "" {
		return problemDetails{}, false
	}
	return pd, true
}

func formatHTTPDownloadProblem(cid, status string, body []byte) error {
	trimmed := strings.TrimSpace(string(body))
	if pd, ok := parseProblemJSON(trimmed); ok {
		return errors.New(formatProblemDownloadMessage(cid, status, pd))
	}
	if i := strings.Index(trimmed, "{"); i >= 0 {
		if pd, ok := parseProblemJSON(trimmed[i:]); ok {
			return errors.New(formatProblemDownloadMessage(cid, status, pd))
		}
	}
	if trimmed == "" {
		return fmt.Errorf("download %s failed: %s", cid, status)
	}
	return fmt.Errorf("download %s failed: %s %s", cid, status, trimmed)
}

func formatProblemDownloadMessage(cid, status string, pd problemDetails) string {
	msg := fmt.Sprintf("download %s failed: %s", cid, status)
	if pd.Title != "" {
		msg += " — " + pd.Title
	}
	if pd.Detail != "" {
		msg += ": " + pd.Detail
	}
	return msg
}
