package v2ray

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	vcore "v2ray.com/core"
	vproxyman "v2ray.com/core/app/proxyman"
	vnet "v2ray.com/core/common/net"
	vsession "v2ray.com/core/common/session"
	vsignal "v2ray.com/core/common/signal"
	vtask "v2ray.com/core/common/task"

	"github.com/eycorsican/go-tun2socks/common/dns"
	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/common/proc"
	"github.com/eycorsican/go-tun2socks/core"
)

type udpConnEntry struct {
	conn net.PacketConn

	// `ReadFrom` method of PacketConn given by V2Ray
	// won't return the correct remote address, we treat
	// all data receive from V2Ray are coming from the
	// same remote host, i.e. the `target` that passed
	// to `Connect`.
	target *net.UDPAddr

	updater vsignal.ActivityUpdater
	ctx     context.Context
}

type udpHandler struct {
	sync.Mutex

	v        *vcore.Instance
	sniffing *vproxyman.SniffingConfig
	conns    map[core.UDPConn]*udpConnEntry
	timeout  time.Duration // Maybe override by V2Ray local policies for some conns.

	fakeDns dns.FakeDns
}

func (h *udpHandler) fetchInput(conn core.UDPConn) {
	h.Lock()
	c, ok := h.conns[conn]
	h.Unlock()
	if !ok {
		return
	}

	buf := make([]byte, 65535)

	defer func() {
		h.Close(conn)
	}()

	for {
		n, addr, err := c.conn.ReadFrom(buf)
		if err != nil && n <= 0 {
			return
		}
		c.updater.Update()
		resolvedAddr, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			log.Warnf("failed to resolve address: %v", err)
			return
		}
		_, err = conn.WriteFrom(buf[:n], resolvedAddr)
		if err != nil {
			return
		}
	}
}

func NewUDPHandler(instance *vcore.Instance, sniffing *vproxyman.SniffingConfig, timeout time.Duration, fakeDns dns.FakeDns) core.UDPConnHandler {
	return &udpHandler{
		v:        instance,
		sniffing: sniffing,
		conns:    make(map[core.UDPConn]*udpConnEntry, 16),
		timeout:  timeout,
		fakeDns:  fakeDns,
	}
}

func (h *udpHandler) Connect(conn core.UDPConn, target *net.UDPAddr) error {
	if target == nil {
		return errors.New("nil target is not allowed")
	}

	var err error
	var processes = []string{"unknown process"}
	// Get name of the process.
	localHost, localPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	localPortInt, _ := strconv.Atoi(localPortStr)
	if list, err := proc.GetProcessesBySocket(target.Network(), localHost, uint16(localPortInt)); err == nil {
		processes = list
	}

	sid := vsession.NewID()
	ctx := vsession.ContextWithID(context.Background(), sid)

	ctx = vsession.ContextWithInbound(ctx, &vsession.Inbound{Tag: "tun2socks"})
	ctx = vproxyman.ContextWithSniffingConfig(ctx, h.sniffing)

	content := vsession.ContentFromContext(ctx)
	if content == nil {
		content = new(vsession.Content)
		ctx = vsession.ContextWithContent(ctx, content)
	}
	content.Application = processes
	content.Network = conn.LocalAddr().Network()
	content.LocalAddr = conn.LocalAddr().String()
	content.RemoteAddr = target.String()

	outbound := vsession.OutboundFromContext(ctx)
	if outbound == nil {
		outbound = new(vsession.Outbound)
		ctx = vsession.ContextWithOutbound(ctx, outbound)
	}
	outbound.Timeout = h.timeout

	ctx, cancel := context.WithCancel(ctx)
	c, err := vcore.DialUDP(ctx, h.v)
	if err != nil {
		return errors.New(fmt.Sprintf("dial V proxy connection failed: %v", err))
	}
	timer := vsignal.CancelAfterInactivity(ctx, cancel, h.timeout)
	h.Lock()
	h.conns[conn] = &udpConnEntry{
		conn:    c,
		target:  target,
		updater: timer,
		ctx:     ctx,
	}
	h.Unlock()
	fetchTask := func() error {
		h.fetchInput(conn)
		return nil
	}
	go func() {
		if err := vtask.Run(ctx, fetchTask); err != nil {
			log.Debugf("failed to fetch UDP: %v", err)
		}
		c.Close()
	}()

	log.Access(processes[0], "", "udp", conn.LocalAddr().String(), target.Network()+":"+target.String())

	return nil
}

func (h *udpHandler) ReceiveTo(conn core.UDPConn, data []byte, addr *net.UDPAddr) error {
	if h.fakeDns != nil {
		if addr.Port == dns.COMMON_DNS_PORT {
			resp, err := h.fakeDns.GenerateFakeResponse(data)
			if err == nil {
				_, err = conn.WriteFrom(resp, addr)
				if err != nil {
					return errors.New(fmt.Sprintf("write dns answer failed: %v", err))
				}
				h.CloseNolog(conn)
				return nil
			}
		}
	}

	h.Lock()
	c, ok := h.conns[conn]
	h.Unlock()

	if ok {
		if addr.Port == dns.COMMON_DNS_PORT {
			_, _, err := dns.ParseDNSQuery(data)
			if err == nil {
				c.updater.SetTimeout(8 * time.Second)
				if sess := vsession.ProxySessionFromContext(c.ctx); sess != nil {
					sess.Extra = "hellow"
				}
			}
		}

		if inbound := vsession.InboundFromContext(c.ctx); inbound != nil {
			inbound.Source = vnet.DestinationFromAddr(conn.LocalAddr())
		}

		n, err := c.conn.WriteTo(data, addr)
		if n > 0 {
			c.updater.Update()
		}
		if err != nil {
			h.Close(conn)
			return errors.New(fmt.Sprintf("write remote failed: %v", err))
		}
		return nil
	} else {
		h.Close(conn)
		return errors.New(fmt.Sprintf("proxy connection %v->%v does not exists", conn.LocalAddr(), addr))
	}
}

func (h *udpHandler) Close(conn core.UDPConn) {
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if c, found := h.conns[conn]; found {
		c.conn.Close()
	}
	delete(h.conns, conn)
}

func (h *udpHandler) CloseNolog(conn core.UDPConn) {
	conn.Close()

	h.Lock()
	defer h.Unlock()

	if c, found := h.conns[conn]; found {
		c.conn.Close()
	}
	delete(h.conns, conn)
}
