package socks

import (
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"github.com/eycorsican/go-tun2socks/common/dns"
	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/common/proc"
	"github.com/eycorsican/go-tun2socks/common/stats"
	"github.com/eycorsican/go-tun2socks/core"
)

type tcpHandler struct {
	sync.Mutex

	proxyHost string
	proxyPort uint16

	fakeDns       dns.FakeDns
	sessionStater stats.SessionStater
}

func NewTCPHandler(proxyHost string, proxyPort uint16, fakeDns dns.FakeDns, sessionStater stats.SessionStater) core.TCPConnHandler {
	return &tcpHandler{
		proxyHost:     proxyHost,
		proxyPort:     proxyPort,
		fakeDns:       fakeDns,
		sessionStater: sessionStater,
	}
}

type direction byte

const (
	dirUplink direction = iota
	dirDownlink
)

func statsCopy(dst io.Writer, src io.Reader, sess *stats.Session, dir direction) (written int64, err error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				switch dir {
				case dirUplink:
					sess.AddUploadBytes(int64(nw))
				case dirDownlink:
					sess.AddDownloadBytes(int64(nw))
				default:
				}
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

type duplexConn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

func (h *tcpHandler) relay(lhs, rhs net.Conn, sess *stats.Session) {
	upCh := make(chan struct{})

	cls := func(dir direction, interrupt bool) {
		lhsDConn, lhsOk := lhs.(duplexConn)
		rhsDConn, rhsOk := rhs.(duplexConn)
		if !interrupt && lhsOk && rhsOk {
			switch dir {
			case dirUplink:
				lhsDConn.CloseRead()
				rhsDConn.CloseWrite()
			case dirDownlink:
				lhsDConn.CloseWrite()
				rhsDConn.CloseRead()
			default:
				panic("unexpected direction")
			}
		} else {
			lhs.Close()
			rhs.Close()
		}
	}

	// Uplink
	go func() {
		var err error
		if h.sessionStater != nil && sess != nil {
			_, err = statsCopy(rhs, lhs, sess, dirUplink)
		} else {
			_, err = io.Copy(rhs, lhs)
		}
		if err != nil {
			log.Warnf("uplink error: %v", err)
			cls(dirUplink, true) // interrupt the conn if the error is not nil (not EOF)
		} else {
			cls(dirUplink, false) // half close uplink direction of the TCP conn if possible
		}
		upCh <- struct{}{}
	}()

	// Downlink
	var err error
	if h.sessionStater != nil && sess != nil {
		_, err = statsCopy(lhs, rhs, sess, dirDownlink)
	} else {
		_, err = io.Copy(lhs, rhs)
	}
	if err != nil {
		log.Warnf("downlink error: %v", err)
		cls(dirDownlink, true)
	} else {
		cls(dirDownlink, false)
	}

	<-upCh // Wait for uplink done.

	if h.sessionStater != nil {
		h.sessionStater.RemoveSession(lhs)
	}
}

func (h *tcpHandler) Handle(conn net.Conn, target *net.TCPAddr) error {
	dialer, err := proxy.SOCKS5("tcp", core.ParseTCPAddr(h.proxyHost, h.proxyPort).String(), nil, nil)
	if err != nil {
		log.Warnf("failed to create SOCKS5 dialer: %v", err)
		return err
	}

	// Replace with a domain name if target address IP is a fake IP.
	var targetHost string
	if h.fakeDns != nil && h.fakeDns.IsFakeIP(target.IP) {
		targetHost = h.fakeDns.QueryDomain(target.IP)
	} else {
		targetHost = target.IP.String()
	}
	dest := net.JoinHostPort(targetHost, strconv.Itoa(target.Port))

	c, err := dialer.Dial(target.Network(), dest)
	if err != nil {
		log.Warnf("failed to dial SOCKS5: %v", err)
		return err
	}

	var process string
	var sess *stats.Session
	if h.sessionStater != nil {
		// Get name of the process.
		localHost, localPortStr, _ := net.SplitHostPort(conn.LocalAddr().String())
		localPortInt, _ := strconv.Atoi(localPortStr)
		process, err = proc.GetCommandNameBySocket(target.Network(), localHost, uint16(localPortInt))
		if err != nil {
			process = "unknown process"
		}

		sess = &stats.Session{
			process,
			target.Network(),
			conn.LocalAddr().String(),
			dest,
			0,
			0,
			time.Now(),
			"",
		}
		h.sessionStater.AddSession(conn, sess)
	}

	go h.relay(conn, c, sess)

	log.Access(process, "proxy", target.Network(), conn.LocalAddr().String(), dest)

	return nil
}
