package v2ray

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	vcore "v2ray.com/core"
	vproxyman "v2ray.com/core/app/proxyman"
	vnet "v2ray.com/core/common/net"
	vsession "v2ray.com/core/common/session"

	"github.com/eycorsican/go-tun2socks/common/dns"
	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/common/proc"
	"github.com/eycorsican/go-tun2socks/core"
)

type tcpHandler struct {
	sync.Mutex
	v        *vcore.Instance
	sniffing *vproxyman.SniffingConfig
	fakeDns  dns.FakeDns
	records  map[net.Conn]*vsession.ProxyRecord
}

type direction byte

const (
	dirUplink direction = iota
	dirDownlink
)

func (h *tcpHandler) relay(lhs net.Conn, rhs net.Conn) {
	var upBytes, downBytes int64
	var err error

	cls := func() {
		lhs.Close()
		rhs.Close()
	}

	// Uplink
	go func() {
		upBytes, err = io.Copy(rhs, lhs)
		cls() // Close the conn anyway.
	}()

	// Downlonk
	downBytes, err = io.Copy(lhs, rhs)
	cls() // Close the conn anyway.

	h.Lock()
	defer h.Unlock()

	record, ok := h.records[lhs]
	if ok {
		record.AddUploadBytes(int32(upBytes))
		record.AddDownloadBytes(int32(downBytes))
		vsession.InsertRecord(record)
	}
	delete(h.records, lhs)
}

func NewTCPHandler(instance *vcore.Instance, sniffing *vproxyman.SniffingConfig, fakeDns dns.FakeDns) core.TCPConnHandler {
	return &tcpHandler{
		v:        instance,
		sniffing: sniffing,
		fakeDns:  fakeDns,
		records:  make(map[net.Conn]*vsession.ProxyRecord, 16),
	}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	dest := vnet.DestinationFromAddr(target)

	// Replace with a domain name if target address IP is a fake IP.
	var shouldSniffDomain = false
	if h.fakeDns != nil {
		if h.fakeDns.IsFakeIP(target.IP) {
			domain := h.fakeDns.QueryDomain(target.IP)
			if len(domain) == 0 {
				shouldSniffDomain = true
				dest.Address = vnet.IPAddress([]byte{1, 2, 3, 4})
			} else {
				dest.Address = vnet.DomainAddress(domain)
			}
		}
	}

	var err error
	var processes = []string{"unknown process"}
	localHost, localPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
	localPortInt, _ := strconv.Atoi(localPortStr)
	if list, err := proc.GetProcessesBySocket(target.Network(), localHost, uint16(localPortInt)); err == nil {
		processes = list
	}

	sid := vsession.NewID()
	ctx := vsession.ContextWithID(context.Background(), sid)

	ctx = vsession.ContextWithInbound(ctx, &vsession.Inbound{Tag: "tun2socks"})
	ctx = vproxyman.ContextWithSniffingConfig(ctx, h.sniffing)

	record := &vsession.ProxyRecord{Target: dest.String(), StartTime: time.Now().UnixNano(), UploadBytes: 0, DownloadBytes: 0, RecordType: 0}
	ctx = vsession.ContextWithProxyRecord(ctx, record)

	content := vsession.ContentFromContext(ctx)
	if content == nil {
		content = new(vsession.Content)
		ctx = vsession.ContextWithContent(ctx, content)
	}
	content.Application = processes
	content.Network = target.Network()
	content.LocalAddr = conn.LocalAddr().String()
	content.RemoteAddr = dest.NetAddr()

	if shouldSniffDomain {
		// Configure sniffing settings for traffic coming from tun2socks.
		sniffingConfig := &vproxyman.SniffingConfig{
			Enabled:             true,
			DestinationOverride: []string{"http", "tls"},
		}
		content.SniffingRequest.Enabled = sniffingConfig.Enabled
		content.SniffingRequest.OverrideDestinationForProtocol = sniffingConfig.DestinationOverride
	}

	c, err := vcore.Dial(ctx, h.v, dest)
	if err != nil {
		return errors.New(fmt.Sprintf("dial V proxy connection failed: %v", err))
	}

	h.Lock()
	h.records[conn] = record
	h.Unlock()

	go h.relay(conn, c)

	log.Access(processes[0], "", target.Network(), conn.LocalAddr().String(), dest.String())

	return nil
}
