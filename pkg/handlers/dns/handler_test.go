package dns

import (
	"net"
	"reflect"
	"testing"
)

func Test_ip2int(t *testing.T) {

	localhostIP := net.ParseIP("127.0.0.1")

	type args struct {
		ip net.IP
	}
	tests := []struct {
		name string
		args args
		want uint32
	}{
		{
			"localhost",
			args{
				ip: localhostIP,
			},
			2130706433,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ip2int(tt.args.ip); got != tt.want {
				t.Errorf("ip2int() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_int2ip(t *testing.T) {
	localhostIP := net.ParseIP("127.0.0.1")

	type args struct {
		nn uint32
	}
	tests := []struct {
		name string
		args args
		want net.IP
	}{
		{
			"localhost",
			args{
				nn: 2130706433,
			},
			localhostIP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := int2ip(tt.args.nn); !reflect.DeepEqual(got.String(), tt.want.String()) {
				t.Errorf("int2ip() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encodeIP(t *testing.T) {
	type args struct {
		rawIP string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			"127.0.0.1",
			args{
				rawIP: "127.0.0.1/32",
			},
			"12lijovyo5pmwcvn",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := encodeIP(tt.args.rawIP); got != tt.want {
				t.Errorf("encodeIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_decodeIP(t *testing.T) {
	type args struct {
		encodedIP string
	}
	tests := []struct {
		name string
		args args
		want string
	}{

		{
			"127.0.0.1",
			args{
				encodedIP: "12lijovyo5pmwcvn",
			},
			"127.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decodeIP(tt.args.encodedIP); got != tt.want {
				t.Errorf("decodeIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
