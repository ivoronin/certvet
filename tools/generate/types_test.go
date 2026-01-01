package generate

import (
	"testing"
	"time"
)

func TestTrustEntry_HasConstraints(t *testing.T) {
	t.Parallel()

	now := time.Now()
	tests := []struct {
		name  string
		entry TrustEntry
		want  bool
	}{
		{"no constraints", TrustEntry{Platform: "windows", Version: "current"}, false},
		{"only NotBeforeMax", TrustEntry{NotBeforeMax: &now}, true},
		{"only DistrustDate", TrustEntry{DistrustDate: &now}, true},
		{"only SCTNotAfter", TrustEntry{SCTNotAfter: &now}, true},
		{"all constraints", TrustEntry{NotBeforeMax: &now, DistrustDate: &now, SCTNotAfter: &now}, true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.entry.HasConstraints(); got != tt.want {
				t.Errorf("TrustEntry.HasConstraints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustEntry_FormatConstraints(t *testing.T) {
	t.Parallel()

	t1 := time.Date(2025, 1, 15, 12, 30, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2024, 11, 12, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name  string
		entry TrustEntry
		wide  bool
		want  string
	}{
		{
			name:  "no constraints",
			entry: TrustEntry{Platform: "android", Version: "14"},
			want:  "-",
		},
		{
			name:  "single NotBeforeMax",
			entry: TrustEntry{NotBeforeMax: &t1},
			want:  "notbefore<2025-01-15",
		},
		{
			name:  "single DistrustDate",
			entry: TrustEntry{DistrustDate: &t2},
			want:  "distrust<2025-06-01",
		},
		{
			name:  "single SCTNotAfter",
			entry: TrustEntry{SCTNotAfter: &t3},
			want:  "sct<2024-11-12",
		},
		{
			name:  "multiple constraints",
			entry: TrustEntry{NotBeforeMax: &t1, DistrustDate: &t2},
			want:  "notbefore<2025-01-15, distrust<2025-06-01",
		},
		{
			name:  "all constraints",
			entry: TrustEntry{NotBeforeMax: &t1, DistrustDate: &t2, SCTNotAfter: &t3},
			want:  "notbefore<2025-01-15, distrust<2025-06-01, sct<2024-11-12",
		},
		{
			name:  "wide mode single",
			entry: TrustEntry{NotBeforeMax: &t1},
			wide:  true,
			want:  "notbefore<2025-01-15T12:30:00Z",
		},
		{
			name:  "wide mode multiple",
			entry: TrustEntry{NotBeforeMax: &t1, SCTNotAfter: &t3},
			wide:  true,
			want:  "notbefore<2025-01-15T12:30:00Z, sct<2024-11-12T00:00:00Z",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.entry.FormatConstraints(tt.wide); got != tt.want {
				t.Errorf("TrustEntry.FormatConstraints(%v) = %q, want %q", tt.wide, got, tt.want)
			}
		})
	}
}

