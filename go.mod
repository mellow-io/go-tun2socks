module github.com/mellow-io/go-tun2socks

go 1.13

require (
	github.com/eycorsican/go-tun2socks v1.16.9
	github.com/google/gopacket v1.1.17
	github.com/miekg/dns v1.1.22
	github.com/shadowsocks/go-shadowsocks2 v0.0.11
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	golang.org/x/net v0.0.0-20191021144547-ec77196f6094
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527
	golang.org/x/text v0.3.2
	v2ray.com/core v4.19.1+incompatible
)

replace github.com/eycorsican/go-tun2socks => /opt/go/src/github.com/mellow-io/go-tun2socks

replace v2ray.com/core => /opt/go/src/github.com/mellow-io/v2ray-core

replace github.com/songgao/water => /opt/go/src/github.com/mellow-io/water
