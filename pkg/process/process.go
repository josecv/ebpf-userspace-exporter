package process

import (
	"fmt"
	"github.com/mitchellh/go-ps"
)

// FindPid finds the PID associated with a given binary name.
// If multiple processes have the same binary name, one will be returned in an undefined manner.
// If the process is not found, -1 is returned.
func FindPid(binaryName string) (int, error) {
	processes, err := ps.Processes()
	if err != nil {
		return -1, fmt.Errorf("Unable to list processes: %s", err)
	}
	for _, process := range processes {
		if process.Executable() == binaryName {
			return process.Pid(), nil
		}
	}
	return -1, nil
}
