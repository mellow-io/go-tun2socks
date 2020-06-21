// +build fakedns

package main

import (
	"flag"
	"strings"

	"github.com/eycorsican/go-tun2socks/common/dns/fakedns"
	"github.com/eycorsican/go-tun2socks/common/log"
)

func init() {
	args.EnableFakeDns = flag.Bool("fakeDns", false, "Enable Fake DNS")
	args.FakeDnsMinIP = flag.String("fakeDnsMinIP", "172.30.0.0", "Minimum fake IP used by Fake DNS")
	args.FakeDnsMaxIP = flag.String("fakeDnsMaxIP", "172.30.16.255", "Maximum fake IP used by Fake DNS")
	args.FakeDnsCacheDir = flag.String("fakeDnsCacheDir", "", "Cache directory used by Fake DNS")
	args.FakeDnsExcludeDomains = flag.String("fakeDnsExcludes", "", "A domain keyword list seperated by comma to exclude domains from Fake DNS")

	addPostFlagsInitFn(func() {
		if *args.EnableFakeDns {
			excludes := strings.Split(*args.FakeDnsExcludeDomains, ",")
			var filters []string
			for _, filter := range excludes {
				filter = strings.TrimSpace(filter)
				if len(filter) == 0 {
					continue
				}
				filters = append(filters, filter)
			}
			fakeDns = fakedns.NewSimpleFakeDns(*args.FakeDnsMinIP, *args.FakeDnsMaxIP, *args.FakeDnsCacheDir, filters)
			err := fakeDns.Start()
			if err != nil {
				log.Errorf("Error starting Fake DNS: %v", err)
			}
		} else {
			fakeDns = nil
		}
	})
}
