package process

import (
	"fmt"
	"github.com/prometheus/procfs"
)

// Finder finds processes that match requested binary attachments
type Finder struct {
	procfs procfs.FS
}

// NewFinder returns a new Finder
func NewFinder() (Finder, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return Finder{}, fmt.Errorf("Unable to build procfs: %s", err)
	}
	return Finder{
		procfs: fs,
	}, nil
}

// FindByBinaryName finds processes that match a given binary name
func (f Finder) FindByBinaryName(binaryName string) (procfs.Procs, error) {
	procs, err := f.procfs.AllProcs()
	if err != nil {
		return procfs.Procs{}, fmt.Errorf("Unable to list processes: %s", err)
	}
	result := procfs.Procs{}
	for _, proc := range procs {
		comm, err := proc.Comm()
		if err != nil {
			return procfs.Procs{}, fmt.Errorf("Unable to get comm for process %d: %s", proc.PID, err)
		}
		if comm == binaryName {
			result = append(result, proc)
		}
	}
	return result, nil
}
