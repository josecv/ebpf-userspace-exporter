package process

import (
	"fmt"
	"github.com/mitchellh/go-ps"
)

// FindPids finds all PIDs associated with a given binary name.
func FindPids(binaryName string) ([]int, error) {
	processes, err := ps.Processes()
	if err != nil {
		return []int{}, fmt.Errorf("Unable to list processes: %s", err)
	}
	results := []int{}
	for _, process := range processes {
		if process.Executable() == binaryName {
			results = append(results, process.Pid())
		}
	}
	return results, nil
}
