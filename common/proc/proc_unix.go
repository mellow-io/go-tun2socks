// +build unix,!linux unix,!darwin

package proc

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	InitProcessID = 1
)

var executableName string

func GetPpidAndCommand(pid int) (int, string, error) {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "ppid=", "-o", "comm=").Output()
	if err != nil {
		if len(out) != 0 {
			return 0, "", errors.New(fmt.Sprintf("%v, output: %s", err, out))
		}
		return 0, "", err
	}
	line := strings.TrimSpace(string(out))
	parts := strings.Split(line, " ")
	if len(parts) < 2 {
		return 0, "", errors.New("not found")
	}
	ppid, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", errors.New("not a number")
	}
	name := path.Base(strings.Join(parts[1:], " "))
	return ppid, name, nil
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
	// lsof with "-c ^xxx" arg will always cause an error
	// if err != nil {
	// 	if len(out) != 0 {
	// 		return 0, errors.New(fmt.Sprintf("%v, output: %s", err, out))
	// 	}
	// 	return 0, err
	// }
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		// There may be multiple candidate
		// sockets in the list, just take
		// the first one for simplicity.
		if strings.HasPrefix(line, "p") {
			pid := line[1:len(line)]
			id, err := strconv.Atoi(pid)
			if err != nil {
				return 0, errors.New("not a number")
			}
			return id, nil
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
