package xlog

import "testing"

func Test_getAppPkg(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "Should get correct package name",
			want: "github.com/defektive/xodbox",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getAppPkg(); got != tt.want {
				t.Errorf("getAppPkg() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_fullPkg(t *testing.T) {
	type args struct {
		l interface{}
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Should get correct package name",
			args: args{l: Test_fullPkg},
			want: "github.com/defektive/xodbox/pkg/xlog",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fullPkg(tt.args.l); got != tt.want {
				t.Errorf("fullPkg() = %v, want %v", got, tt.want)
			}
		})
	}
}
