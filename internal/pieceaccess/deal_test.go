package pieceaccess

import (
	"encoding/json"
	"testing"
)

func TestDealTypeStringAndParse(t *testing.T) {
	t.Parallel()
	cases := []struct {
		t    DealType
		want string
	}{
		{DealTypePublic, "public"},
		{DealTypePrivate, "private"},
		{DealTypeUnknown, "unknown"},
		{DealType(99), "unknown"},
	}
	for _, tc := range cases {
		if got := tc.t.String(); got != tc.want {
			t.Fatalf("%v.String()=%q want %q", tc.t, got, tc.want)
		}
	}

	parseCases := []struct {
		in   string
		want DealType
	}{
		{"PUBLIC", DealTypePublic},
		{"public", DealTypePublic},
		{"10", DealTypePublic},
		{"PRIVATE", DealTypePrivate},
		{"20", DealTypePrivate},
		{"", DealTypeUnknown},
		{"other", DealTypeUnknown},
	}
	for _, tc := range parseCases {
		if got := ParseDealType(tc.in); got != tc.want {
			t.Fatalf("ParseDealType(%q)=%v want %v", tc.in, got, tc.want)
		}
	}
}

func TestDealTypeMarshalJSON(t *testing.T) {
	t.Parallel()
	b, err := json.Marshal(DealTypePrivate)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"private"` {
		t.Fatalf("got %s", b)
	}
}
