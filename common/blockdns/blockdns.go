// +build !windows

package blockdns

import (
	"errors"
)

func FixDnsLeakage(tunName string) error {
	return errors.New("not implemented")
}
