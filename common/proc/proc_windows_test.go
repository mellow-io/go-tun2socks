package proc

import (
	"net"
	"strconv"
	"testing"
)

func TestGetCommandBySocket(t *testing.T) {
	conn, err := net.Dial("tcp", "114.114.114.114:53")
	if err != nil {
		t.Errorf("failed to dial target: %v", err)
	}
	laddr := conn.LocalAddr()
	host, port, err := net.SplitHostPort(laddr.String())
	portInt, err := strconv.Atoi(port)
	if err != nil {
		t.Errorf("invalid port: %v", err)
	}
	_, err := GetProcessesBySocket(laddr.Network(), host, uint16(portInt))
	if err != nil {
		t.Errorf("get command failed: %v", err)
	}
}
