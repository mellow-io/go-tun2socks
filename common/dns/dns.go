package dns

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

const COMMON_DNS_PORT = 53

type DnsCache interface {
	// Query queries the response for the DNS request with payload `p`,
	// the response data should be a valid DNS response payload.
	Query(p []byte) []byte

	// Store stores the DNS response with payload `p` to the cache.
	Store(p []byte)
}

type IPCache interface {
	Query(string) []net.IP
	Store(string, []net.IP, uint32)
}

type FakeDns interface {
	Start() error
	Stop() error

	// GenerateFakeResponse generates a fake dns response for the specify request.
	GenerateFakeResponse(request []byte) ([]byte, error)

	// QueryDomain returns the corresponding domain for the given IP.
	QueryDomain(ip net.IP) string

	// IsFakeIP checks if the given ip is a fake IP.
	IsFakeIP(ip net.IP) bool
}

func ParseDNSQuery(p []byte) (string, string, error) {
	req := new(dns.Msg)
	err := req.Unpack(p)
	if err != nil {
		return "", "", fmt.Errorf("unpack message failed")
	}
	if len(req.Question) != 1 {
		return "", "", fmt.Errorf("multi-question")
	}
	var qt string
	qtype := req.Question[0].Qtype
	switch qtype {
	case dns.TypeA:
		qt = "TypeA"
	case dns.TypeAAAA:
		qt = "TypeAAAA"
	default:
		return "", "", fmt.Errorf("wrong query type")
	}
	qclass := req.Question[0].Qclass
	if qclass != dns.ClassINET {
		return "", "", fmt.Errorf("wrong query class")
	}
	fqdn := req.Question[0].Name
	domain := fqdn[:len(fqdn)-1]
	if _, ok := dns.IsDomainName(domain); !ok {
		return "", "", fmt.Errorf("invalid domain")
	}
	return qt, domain, nil
}
