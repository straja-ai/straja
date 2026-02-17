package strajad

import "testing"

func TestSafeHNSWTopK(t *testing.T) {
	tests := []struct {
		name        string
		limit       int
		current     int
		active      int
		efSearch    int
		wantSafeTop int
	}{
		{name: "zero_limit", limit: 0, current: 100, active: 100, efSearch: 64, wantSafeTop: 0},
		{name: "zero_current", limit: 10, current: 0, active: 100, efSearch: 64, wantSafeTop: 0},
		{name: "clamp_current", limit: 10, current: 3, active: 100, efSearch: 64, wantSafeTop: 3},
		{name: "clamp_active", limit: 20, current: 100, active: 5, efSearch: 64, wantSafeTop: 5},
		{name: "clamp_ef", limit: 200, current: 1000, active: 1000, efSearch: 64, wantSafeTop: 64},
		{name: "ignore_zero_active", limit: 9, current: 50, active: 0, efSearch: 64, wantSafeTop: 9},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := safeHNSWTopK(tc.limit, tc.current, tc.active, tc.efSearch)
			if got != tc.wantSafeTop {
				t.Fatalf("safeHNSWTopK(limit=%d,current=%d,active=%d,ef=%d)=%d want=%d",
					tc.limit, tc.current, tc.active, tc.efSearch, got, tc.wantSafeTop)
			}
		})
	}
}
