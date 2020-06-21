// +build linux,!android

package proc

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const (
	InitProcessID = 1
)

var executableName string

func getPidByIno(ino int) (int, error) {
	procDir := "/proc"
	fis, err := ioutil.ReadDir(procDir)
	if err != nil {
		return 0, err
	}
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(fi.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procDir, fi.Name(), "fd")
		fis2, err := ioutil.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fi2 := range fis2 {
			var stat syscall.Stat_t
			f := filepath.Join(fdDir, fi2.Name())
			err = syscall.Stat(f, &stat)
			if err != nil {
				continue
			}
			if int(stat.Ino) == ino {
				return pid, nil
			}
		}
	}
	return 0, errors.New("not found")
}

// GetPpidAndCommand(pid int) (int, string, error)
//
// 1. Read /proc/[pid]/stat and scan for comm and ppid
//
// Example:
// 555 (UVM global queu) S 2 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 443 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 0 0 0 17 4 0 0 0 0 0 0 0 0 0 0 0 0 0
//
func GetPpidAndCommand(pid int) (int, string, error) {
	filePath := fmt.Sprintf("/proc/%d/stat", pid)
	file, err := os.Open(filePath)
	if err != nil {
		return 0, "", err
	}
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanRunes)

	// Skip the first field.
	//
	// Example:
	// Skip "555 "
	for scanner.Scan() {
		if scanner.Text() == " " {
			break
		}
	}

	// Scan command name.
	//
	// Example:
	// Parsing "(UVM global queu) "
	scanningComm := false
	comm := ""
	for scanner.Scan() {
		if !scanningComm && scanner.Text() == " " {
			break
		}
		if scanner.Text() == ")" {
			scanningComm = false
			continue
		}
		if scanningComm {
			comm += scanner.Text()
			continue
		}
		if scanner.Text() == "(" {
			scanningComm = true
			continue
		}
	}

	if len(comm) == 0 {
		return 0, "", errors.New("command not found")
	}

	// Skip the third field.
	//
	// Example:
	// Skip "S "
	for scanner.Scan() {
		if scanner.Text() == " " {
			break
		}
	}

	// Scan Ppid.
	//
	// Example:
	// Parsing "2 "
	ppidStr := ""
	for scanner.Scan() {
		if scanner.Text() == " " {
			break
		} else {
			ppidStr += scanner.Text()
			continue
		}
	}

	ppid, err := strconv.Atoi(ppidStr)
	if err != nil {
		return 0, "", err
	}

	return ppid, comm, nil
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

// GetPidBySocket(network, addr string, port uint16) (int, error)
//
// 1. Read /proc/net/[tcp/udp] table according to network
// 2. Find socket inode number according to addr, port
// 3. Walk through /proc/[pid]/fd, find the matching inode and return the owning pid
//
func GetPidBySocket(network, addr string, port uint16) (int, error) {
	var table string

	switch network {
	case "tcp":
		table = "/proc/net/tcp"
	case "udp":
		table = "/proc/net/udp"
	default:
		return 0, errors.New("invalid network")
	}

	file, err := os.Open(table)
	if err != nil {
		return 0, err
	}

	// cat /proc/net/tcp
	//  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
	//   5: 6800000A:0016 6500000A:E816 01 00000000:00000000 02:000712BC 00000000     0        0 18136 2 0000000000000000 20 4 31 10 9
	//   6: 6800000A:CBB4 72727272:0035 01 00000000:00000000 00:00000000 00000000  1000        0 17180 1 0000000000000000 300 0 0 10 -1
	//
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(strings.Trim(scanner.Text(), " "))
		if len(fields) < 12 {
			continue
		}
		if !strings.Contains(fields[0], ":") {
			continue
		}
		tmp := strings.Split(fields[1], ":")
		if len(tmp) != 2 {
			continue
		}

		// s, err := strconv.ParseInt(tmp[0], 16, 32)
		// if err != nil {
		//     return 0, fmt.Errorf("parse addr failed: %v", err)
		// }
		// b := make([]byte, 4)
		// binary.LittleEndian.PutUint32(b, uint32(s))
		// n := binary.BigEndian.Uint32(b)
		// ip := net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))

		port2, err := strconv.ParseInt(tmp[1], 16, 32)
		if err != nil {
			return 0, fmt.Errorf("parse port failed: %v", err)
		}

		if /* addr == ip.String() && */ port == uint16(port2) {
			inode, err := strconv.Atoi(fields[9])
			if err != nil {
				return 0, fmt.Errorf("parse inode failed: %v", err)
			}
			pid, err := getPidByIno(inode)
			if err != nil {
				return 0, err
			}
			return pid, nil
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
