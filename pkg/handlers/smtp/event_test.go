package smtp

import (
	"testing"
)

func TestActionStringCoversAllConstants(t *testing.T) {
	tests := []struct {
		action Action
		want   string
	}{
		{PasswordAuth, "PasswordAuth"},
		{Mail, "Mail"},
		{Rcpt, "Rcpt"},
		{Data, "Data"},
		{Reset, "Reset"},
		{Logout, "Logout"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if got := tc.action.String(); got != tc.want {
				t.Errorf("Action(%d).String() = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}
