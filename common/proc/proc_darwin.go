// +build darwin,!ios

package proc

/*
#include <netinet/in.h>
#include <arpa/inet.h>

#include "libproc.h"
*/
import "C"
import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"
)

const (
	InitProcessID = 1
)

var executableName string

func getSocketInfo(pid C.int, fd C.int32_t) (string, string, uint16, error) {
	var bufUsed int
	var si C.struct_socket_fdinfo

	bufUsed = int(C.proc_pidfdinfo(
		pid,
		fd,
		C.PROC_PIDFDSOCKETINFO,
		unsafe.Pointer(&si),
		C.int(unsafe.Sizeof(si))))
	if bufUsed <= 0 {
		return "", "", 0, fmt.Errorf("proc_pidfdinfo() failed")
	}

	buf := make([]byte, 2)
	var network string
	var lp uint16
	var str [int(C.INET_ADDRSTRLEN)]C.char

	fam := si.psi.soi_family
	if fam == C.AF_INET {
		proto := si.psi.soi_protocol
		if proto == C.IPPROTO_TCP || proto == C.IPPROTO_UDP {
			if si.psi.soi_kind == C.SOCKINFO_TCP {
				priTcp := (*C.struct_tcp_sockinfo)(unsafe.Pointer(&si.psi.soi_proto[0]))
				ina46 := (*C.struct_in4in6_addr)(unsafe.Pointer(&priTcp.tcpsi_ini.insi_laddr[0]))
				la := ina46.i46a_addr4
				C.inet_ntop(
					C.AF_INET,
					unsafe.Pointer(&la),
					&str[0],
					C.INET_ADDRSTRLEN)
				lp = uint16(priTcp.tcpsi_ini.insi_lport)
				network = "tcp"
			} else {
				priIn := (*C.struct_in_sockinfo)(unsafe.Pointer(&si.psi.soi_proto[0]))
				ina46 := (*C.struct_in4in6_addr)(unsafe.Pointer(&priIn.insi_laddr[0]))
				la := ina46.i46a_addr4
				C.inet_ntop(
					C.AF_INET,
					unsafe.Pointer(&la),
					&str[0],
					C.INET_ADDRSTRLEN)
				lp = uint16(priIn.insi_lport)
				network = "udp"
			}
			binary.BigEndian.PutUint16(buf, lp)
			port := binary.LittleEndian.Uint16(buf)
			return network, C.GoString(&str[0]), port, nil
		}
	}
	return "", "", 0, fmt.Errorf("not found")
}

func GetPpidAndCommand(pid int) (int, string, error) {
	var bufUsed int
	var tai C.struct_proc_taskallinfo
	bufUsed = int(C.proc_pidinfo(
		C.int(pid),
		C.PROC_PIDTASKALLINFO,
		0,
		unsafe.Pointer(&tai),
		C.int(unsafe.Sizeof(tai))))
	if bufUsed <= 0 {
		return 0, "", errors.New("proc_pidinfo() failed")
	}
	return int(tai.pbsd.pbi_ppid), C.GoString(&tai.pbsd.pbi_name[0]), nil
}

func GetProcessesBySocket(network string, addr string, port uint16) ([]string, error) {
	var processes []string
	var err error
	pid, err := GetPidBySocket(network, addr, port)
	if err != nil {
		return nil, err
	}
	for {
		ppid, comm, err := GetPpidAndCommand(pid)
		if err != nil {
			break
		}
		processes = append(processes, comm)
		if ppid == InitProcessID {
			break
		}
		pid = ppid
	}
	if len(processes) == 0 {
		return nil, errors.New("not found")
	}
	return processes, nil
}

func GetPidBySocket(network string, addr string, port uint16) (int, error) {
	numPids := 0
	pidsSize := 0
	var pids []C.int
	var bufUsed int

	intSize := int(C.sizeof_int)

	bufUsed = int(C.proc_listpids(C.PROC_ALL_PIDS, 0, nil, 0))
	if bufUsed <= 0 {
		return 0, fmt.Errorf("proc_listpids() failed")
	}

	for {
		if bufUsed > pidsSize {
			pidsSize = bufUsed
			pidListLen := int(pidsSize / intSize)
			pids = make([]C.int, pidListLen)
		}
		bufUsed = int(C.proc_listpids(
			C.PROC_ALL_PIDS,
			0,
			unsafe.Pointer(&pids[0]),
			C.int(pidsSize)))
		if bufUsed <= 0 {
			return 0, fmt.Errorf("proc_listpids() failed")
		}
		if bufUsed+intSize >= pidsSize {
			bufUsed = pidsSize + intSize
			continue
		}
		numPids = int(bufUsed / intSize)
		break
	}

	var tai C.struct_proc_taskallinfo

	for i := 0; i < numPids; i++ {
		bufUsed = int(C.proc_pidinfo(
			pids[i],
			C.PROC_PIDTASKALLINFO,
			0,
			unsafe.Pointer(&tai),
			C.int(unsafe.Sizeof(tai))))
		if bufUsed <= 0 {
			continue
		}

		var fdi C.struct_proc_fdinfo
		n := int(tai.pbsd.pbi_nfiles)
		if n > 0 {
			nbFds := int(unsafe.Sizeof(fdi)) * n
			fds := make([]C.struct_proc_fdinfo, nbFds)
			bufUsed = int(C.proc_pidinfo(
				pids[i],
				C.PROC_PIDLISTFDS,
				0,
				unsafe.Pointer(&fds[0]),
				C.int(nbFds)))
			if bufUsed <= 0 {
				continue
			}
			numFds := int(bufUsed / int(unsafe.Sizeof(fdi)))
			for j := 0; j < numFds; j++ {
				if fds[j].proc_fdtype == C.PROX_FDTYPE_SOCKET {
					network2, addr2, port2, err := getSocketInfo(pids[i], fds[j].proc_fd)
					if err != nil {
						continue
					}
					if network == network2 {
						switch network {
						case "tcp":
							if addr == addr2 &&
								port == port2 {
								return int(pids[i]), nil
							}
						case "udp":
							if port == port2 {
								return int(pids[i]), nil
							}
						default:
						}
					}
				}
			}
		}
	}
	return 0, errors.New("not found")
}

func GetCommandNameBySocket(network string, addr string, port uint16) (string, error) {
	pattern := ""
	switch network {
	case "tcp":
		pattern = fmt.Sprintf("-i%s@%s:%d", network, addr, port)
	case "udp":
		// The current approach isn't quite accurate for
		// udp sockets, as more than one processes can
		// listen on the same udp port. Moreover, if
		// the application closes the socket immediately
		// after sending out the packet (e.g. it just
		// uploading data but not receving any data),
		// we may not be able to find it.
		pattern = fmt.Sprintf("-i%s:%d", network, port)
	default:
	}
	var args []string
	if len(executableName) > 0 {
		args = []string{"-c", "^" + executableName, "-n", "-P", "-Fc", pattern}
	} else {
		args = []string{"-n", "-P", "-Fc", pattern}
	}
	out, _ := exec.Command("lsof", args...).Output()
	// if err != nil {
	// 	if len(out) != 0 {
	// 		return "", errors.New(fmt.Sprintf("%v, output: %s", err, out))
	// 	}
	// 	return "", err
	// }
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		// There may be multiple candidate
		// sockets in the list, just take
		// the first one for simplicity.
		if strings.HasPrefix(line, "c") {
			name := line[1:len(line)]
			unquotedName, err := strconv.Unquote(`"` + name + `"`)
			if err != nil {
				return "", fmt.Errorf("failed to unquote process name %v: %v", name, err)
			}
			return unquotedName, nil
		}
	}
	return "", errors.New("not found")
}

func init() {
	if exec, err := os.Executable(); err == nil {
		executableName = filepath.Base(exec)
	}
}
