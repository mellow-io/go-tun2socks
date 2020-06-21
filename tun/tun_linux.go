package tun

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

func OpenTunDevice(name, addr, gw, mask string, dnsServers []string) (io.ReadWriteCloser, error) {
	cfg := water.Config{
		DeviceType: water.TUN,
	}
	cfg.Name = name
	tunDev, err := water.New(cfg)
	if err != nil {
		return nil, err
	}
	name = tunDev.Name()

	ipMask := net.IPMask(net.ParseIP(mask).To4())
	maskSize, _ := ipMask.Size()

	params := fmt.Sprintf("addr add %s/%d dev %s", gw, maskSize, name)
	out, err := exec.Command("ip", strings.Split(params, " ")...).Output()
	if err != nil {
		if len(out) != 0 {
			return nil, errors.New(fmt.Sprintf("%v, output: %s", err, out))
		}
		return nil, err
	}

	params = fmt.Sprintf("link set dev %s up", name)
	out, err = exec.Command("ip", strings.Split(params, " ")...).Output()
	if err != nil {
		if len(out) != 0 {
			return nil, errors.New(fmt.Sprintf("%v, output: %s", err, out))
		}
		return nil, err
	}

	return tunDev, nil
}
