package filter

import (
	"io"
	"time"

	"github.com/eycorsican/go-tun2socks/common/log"
	"github.com/eycorsican/go-tun2socks/common/packet"
)

type icmpEchoFilter struct {
	writer io.Writer
	delay  int
}

func NewICMPEchoFilter(w io.Writer, delay int) Filter {
	return &icmpEchoFilter{writer: w, delay: delay}
}

func (w *icmpEchoFilter) Write(buf []byte) (int, error) {
	if uint8(buf[9]) == packet.PROTOCOL_ICMP {
		payload := make([]byte, len(buf))
		copy(payload, buf)
		go func(data []byte) {
			time.Sleep(time.Duration(w.delay) * time.Millisecond)
			_, err := w.writer.Write(data)
			if err != nil {
				log.Fatalf("failed to input data to the stack: %v", err)
			}
		}(payload)
		return len(buf), nil
	} else {
		return w.writer.Write(buf)
	}
}
