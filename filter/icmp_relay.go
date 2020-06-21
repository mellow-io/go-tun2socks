package filter

import (
	"io"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/common/packet"
	"github.com/eycorsican/go-tun2socks/core"
)

type icmpRelayFilter struct {
	writer      io.Writer
	tunDev      io.Writer
	sendThrough string
	privileged  bool
}

func NewICMPRelayFilter(w io.Writer, tunDev io.Writer, sendThrough string, privileged bool) Filter {
	return &icmpRelayFilter{writer: w, tunDev: tunDev, sendThrough: sendThrough, privileged: privileged}
}

func (w *icmpRelayFilter) Write(buf []byte) (int, error) {
	if uint8(buf[9]) == packet.PROTOCOL_ICMP &&
		packet.IPVERSION_4 == packet.PeekIPVersion(buf) {
		packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default) // copy
		if ip4Layer := packet.Layer(layers.LayerTypeIPv4); ip4Layer != nil {
			if ip4, ok := ip4Layer.(*layers.IPv4); ok {
				go w.relayICMPv4(ip4.Payload, ip4.SrcIP, ip4.DstIP)
			} else {
				log.Errorf("error convert IPv4 layer")
			}
		}
		return len(buf), nil
	} else {
		return w.writer.Write(buf)
	}
}

func (w *icmpRelayFilter) relayICMPv4(data []byte, srcIP, dstIP net.IP) {
	var network string
	var dstAddr net.Addr

	if w.privileged {
		network = "ip4:icmp"
		dstAddr = &net.IPAddr{IP: dstIP}
	} else {
		network = "udp4"
		dstAddr = &net.UDPAddr{IP: dstIP}
	}

	conn, err := icmp.ListenPacket(network, w.sendThrough)
	if err != nil {
		log.Errorf("listen ICMP failed: %v", err)
		return
	}
	defer conn.Close()

	wg := new(sync.WaitGroup)

	if runtime.GOOS == "windows" {
		wg.Add(1)

		go func() {
			defer wg.Done()

			buf := core.NewBytes(core.BufSize)
			defer core.FreeBytes(buf)

			conn.SetReadDeadline(time.Now().Add(4 * time.Second))
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				log.Debugf("read remote failed: %v", err)
				return
			}

			ip := &layers.IPv4{
				Version:  4,
				IHL:      5,
				Length:   uint16(20 + n),
				TTL:      64,
				Id:       2048,
				SrcIP:    dstIP,
				DstIP:    srcIP,
				Protocol: layers.IPProtocolICMPv4,
			}
			pktbuf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{ComputeChecksums: true}
			err = gopacket.SerializeLayers(pktbuf, opts, ip, gopacket.Payload(buf[:n]))
			if err != nil {
				log.Debugf("serialize packet failed: %v", err)
				return
			}

			w.tunDev.Write(pktbuf.Bytes())
		}()
	}

	wg.Add(1)

	go func() {
		defer wg.Done()

		for {
			conn.SetWriteDeadline(time.Now().Add(2 * time.Millisecond))
			if _, err := conn.WriteTo(data, dstAddr); err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Err == syscall.ENOBUFS {
						log.Debugf("failed to send ICMP packet: %v", err)
						continue
					}
				}
				log.Debugf("failed to send ICMP packet: %v", err)
			}
			return
		}
	}()

	wg.Wait()
}
