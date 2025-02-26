package dns

import (
	"encoding/binary"
	"fmt"
	types2 "github.com/defektive/xodbox/pkg/types"
	"github.com/factomproject/basen"
	"github.com/miekg/dns"
	"net"
	"net/url"
	"strconv"
)

//goland:noinspection SpellCheckingInspection
const Base36String string = "0123456789abcdefghijklmnopqrstuvwxyz"

type Handler struct {
	name              string
	Listener          string
	DefaultResponseIP string

	dispatchChannel chan types2.InteractionEvent
}

func NewHandler(handlerConfig map[string]string) types2.Handler {
	listener := handlerConfig["listener"]
	defaultResponseIP := handlerConfig["default_ip"]

	return &Handler{
		name:              "DNS",
		Listener:          listener,
		DefaultResponseIP: defaultResponseIP,
	}
}

type Event struct {
	*types2.BaseEvent
	msg *dns.Msg
}

func newEvent(w dns.ResponseWriter, req *dns.Msg) types2.InteractionEvent {
	remoteAddr := w.RemoteAddr().String()
	remoteAddrURL := fmt.Sprintf("dns://%s", remoteAddr)
	parsedURL, _ := url.Parse(remoteAddrURL)
	portNum, _ := strconv.Atoi(parsedURL.Port())

	return &Event{
		BaseEvent: &types2.BaseEvent{
			RemoteAddr:       parsedURL.Hostname(),
			RemotePortNumber: portNum,
			UserAgentString:  "unknown",
			RawData:          []byte(req.String()),
		},
		msg: req,
	}
}

func (e *Event) Details() string {
	qq := ""
	for _, q := range e.msg.Question {
		if q.Name != "" {
			qq = fmt.Sprintf("%s %d", q.Name, q.Qtype)
			break
		}
	}

	return fmt.Sprintf("DNS: %s", qq)
}

func (h *Handler) dispatchEvent(w dns.ResponseWriter, req *dns.Msg) {
	e := newEvent(w, req)
	h.dispatchChannel <- e
}

func (h *Handler) Name() string {
	return "DNS"
}

func (h *Handler) Start(app types2.App, eventChan chan types2.InteractionEvent) error {

	h.dispatchChannel = eventChan
	responseValue := net.ParseIP(h.DefaultResponseIP).To4()

	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {

		go h.dispatchEvent(w, req)

		var resp dns.Msg
		resp.SetReply(req)
		for _, q := range req.Question {
			a := dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: responseValue,
			}
			resp.Answer = append(resp.Answer, &a)
			w.WriteMsg(&resp)
		}
	})

	lg().Info("Starting DNS server", "listener", h.Listener)
	err := dns.ListenAndServe(h.Listener, "udp", nil)
	if err != nil {
		lg().Error("Failed to start DNS server", "listener", h.Listener, "err", err)
		return err
	}
	return nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

func decodeIP(encodedIP string) string {
	var base36 = basen.NewEncoding(Base36String)
	val, err := base36.DecodeString(encodedIP)
	if err != nil {
		lg().Error("error decoding base36 ip", "err", err)
		ip := net.ParseIP("127.0.0.1")
		return ip.String()
	}

	ipInt, err := strconv.ParseInt(string(val), 10, 32)

	return int2ip(uint32(ipInt)).String()
}

func encodeIP(rawIP string) string {
	var base36 = basen.NewEncoding(Base36String)

	ip, ipNet, err := net.ParseCIDR(rawIP)
	if err != nil {
		lg().Error("error encoding base36 ip", "err", err)
		return ""
	}
	fmt.Println(rawIP, "-> ip:", ip, " net:", ipNet)
	s := ip2int(ip)
	b := []byte(string(s))
	return base36.EncodeToString(b)
}
