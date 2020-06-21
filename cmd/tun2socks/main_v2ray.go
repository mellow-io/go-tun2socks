// +build v2ray

package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"runtime"
	"strings"

	"github.com/miekg/dns"
	vcore "v2ray.com/core"
	vproxyman "v2ray.com/core/app/proxyman"
	vbytespool "v2ray.com/core/common/bytespool"
	vdice "v2ray.com/core/common/dice"
	vnet "v2ray.com/core/common/net"
	vinternet "v2ray.com/core/transport/internet"

	cdns "github.com/eycorsican/go-tun2socks/common/dns"
	dnscache "github.com/eycorsican/go-tun2socks/common/dns/cache"
	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/core"
	"github.com/eycorsican/go-tun2socks/proxy/v2ray"
)

type Resolver struct {
	dns        *dns.Client
	dnsServers []string
	cache      cdns.IPCache
}

func (r *Resolver) Resolve(domain string) ([]net.IP, error) {
	ips := r.cache.Query(domain)
	if len(ips) > 0 {
		return ips, nil
	}

	var lastErr error
	for _, s := range r.dnsServers {
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(domain), t)
			m.RecursionDesired = true
			r, _, err := r.dns.Exchange(m, net.JoinHostPort(s, "53"))
			if err != nil {
				lastErr = fmt.Errorf("DNS exchange failed: %v", err)
				continue
			}
			if r.Rcode != dns.RcodeSuccess {
				lastErr = fmt.Errorf("DNS query not success %v", r.Rcode)
				continue
			}

			var ips []net.IP
			for _, a := range r.Answer {
				switch t {
				case dns.TypeA:
					if r, ok := a.(*dns.A); ok {
						ips = append(ips, r.A)
					}
				case dns.TypeAAAA:
					if r, ok := a.(*dns.AAAA); ok {
						ips = append(ips, r.AAAA)
					}
				}
			}
			if len(ips) > 0 {
				return ips, nil
			}
			lastErr = fmt.Errorf("DNS query failed, no eligible result found.")
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("no eligible result found.")
}

type ResolverDialer struct {
	resolver *Resolver
	dialer   vinternet.SystemDialer
}

func (d *ResolverDialer) Dial(ctx context.Context, source vnet.Address, destination vnet.Destination, sockopt *vinternet.SocketConfig) (net.Conn, error) {
	if destination.Address.Family().IsDomain() {
		domain := destination.Address.Domain()
		ips, err := d.resolver.Resolve(domain)
		if err != nil {
			return nil, err
		}
		destination = vnet.Destination{
			Network: destination.Network,
			Address: vnet.IPAddress(ips[vdice.Roll(len(ips))]),
			Port:    destination.Port,
		}
		return d.dialer.Dial(ctx, source, destination, sockopt)
	}
	return d.dialer.Dial(ctx, source, destination, sockopt)
}

func init() {
	args.addFlag(fUdpTimeout)

	args.VConfig = flag.String("vconfig", "config.json", "Config file for v2ray, in JSON format, and note that routing in v2ray could not violate routes in the routing table")
	args.SniffingType = flag.String("sniffingType", "http,tls", "Enable domain sniffing for specific kind of traffic in v2ray")

	registerHandlerCreater("v2ray", func() {
		core.SetBufferPool(vbytespool.GetPool(core.BufSize))

		sendThroughIP := net.ParseIP(*args.SendThrough)
		if sendThroughIP != nil {
			// V2Ray send through.
			vinternet.SendThroughIP = sendThroughIP

			// Go net package send through.
			net.DefaultResolver = &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
					var localAddr net.Addr
					if strings.Contains(network, "udp") {
						localAddr = &net.UDPAddr{
							IP:   sendThroughIP,
							Port: 0,
						}
					} else if strings.Contains(network, "tcp") {
						localAddr = &net.TCPAddr{
							IP:   sendThroughIP,
							Port: 0,
						}
					} else {
						return nil, fmt.Errorf("unsupported network: %v", network)
					}
					dialer := &net.Dialer{
						DualStack: true,
						LocalAddr: localAddr,
					}
					return dialer.DialContext(ctx, network, addr)
				},
			}

			if runtime.GOOS == "windows" {
				dnsServers := strings.Split(*args.TunDns, ",")
				if len(dnsServers) == 0 {
					dnsServers = []string{"223.5.5.5", "1.1.1.1"}
				}
				resolver := &Resolver{
					dns: &dns.Client{
						Dialer: &net.Dialer{
							LocalAddr: &net.UDPAddr{
								IP:   sendThroughIP,
								Port: 0,
							},
						},
					},
					dnsServers: dnsServers,
					cache:      dnscache.NewSimpleIPCache(),
				}
				vinternet.UseAlternativeSystemDialer(&ResolverDialer{
					resolver: resolver,
					dialer:   &vinternet.DefaultSystemDialer{}})
			}
		}

		configBytes, err := ioutil.ReadFile(*args.VConfig)
		if err != nil {
			log.Fatalf("invalid vconfig file")
		}
		var validSniffings []string
		sniffings := strings.Split(*args.SniffingType, ",")
		for _, s := range sniffings {
			if s == "http" || s == "tls" {
				validSniffings = append(validSniffings, s)
			}
		}

		v, err := vcore.StartInstance("json", configBytes)
		if err != nil {
			log.Fatalf("start V instance failed: %v", err)
		}

		sniffingConfig := &vproxyman.SniffingConfig{
			Enabled:             true,
			DestinationOverride: validSniffings,
		}
		if len(validSniffings) == 0 {
			sniffingConfig.Enabled = false
		}

		core.RegisterTCPConnHandler(v2ray.NewTCPHandler(v, sniffingConfig, fakeDns))
		core.RegisterUDPConnHandler(v2ray.NewUDPHandler(v, sniffingConfig, *args.UdpTimeout, fakeDns))
	})
}
