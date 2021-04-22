package usdt

import (
	"fmt"
	"github.com/iovisor/gobpf/bcc"
	"strings"
	"sync"
	"unsafe"
)

/*
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_common.h>
#include <bcc/libbpf.h>
#include <bcc/bcc_usdt.h>


void uprobe_cb_gateway (const char *path, const char *fn_name, uint64_t addr, int pid);
*/
import "C"

// Context is the attached usdt context for a particular pid
type Context struct {
	Pid     int
	context unsafe.Pointer
	closed  bool
}

// NewContext returns a new usdt context for a given pid.
// The supplied code and cflags will be used to compile the module in CompileModule
func NewContext(pid int) (*Context, error) {
	context := C.bcc_usdt_new_frompid(C.int(pid), nil)
	if context == nil {
		return nil, fmt.Errorf("Unable to initialize USDT context")
	}
	return &Context{
		Pid:     pid,
		context: context,
		closed:  false,
	}, nil
}

// Close closes a Context. After this it cannot be used.
func (c *Context) Close() {
	if c.closed {
		return
	}
	C.bcc_usdt_close(c.context)
	c.closed = true
}

// EnableProbe enables a probe
func (c *Context) EnableProbe(probe, fnName string) error {
	if c.closed {
		return fmt.Errorf("Context is closed")
	}
	parts := strings.Split(probe, ":")
	var ret int
	if len(parts) == 1 {
		ret = int(C.bcc_usdt_enable_probe(c.context, C.CString(probe), C.CString(fnName)))
	} else {
		providerName, probeName := parts[0], parts[1]
		ret = int(C.bcc_usdt_enable_fully_specified_probe(c.context, C.CString(providerName), C.CString(probeName), C.CString(fnName)))
	}
	if ret != 0 {
		return fmt.Errorf("Failed to enable function %s for USDT probe %s; is the probe built into the target?", fnName, probe)
	}
	return nil
}

// AddUSDTArguments augments the originalCode with USDT arguments needed to allow the probes to compile
func (c *Context) AddUSDTArguments(originalCode string) (string, error) {
	if c.closed {
		return originalCode, fmt.Errorf("Context is closed")
	}
	fullText := C.GoString(C.bcc_usdt_genargs(&c.context, C.int(1))) + originalCode
	return fullText, nil
}

type uprobeCbArg struct {
	path   string
	fnName string
	addr   uint64
	pid    int
}

var uprobes []uprobeCbArg
var uprobeMu sync.Mutex

//export uprobeCb
func uprobeCb(path, fnName *C.char, addr uint64, pid int) {
	uprobes = append(uprobes, uprobeCbArg{C.GoString(path), C.GoString(fnName), addr, pid})
}

// AttachUprobes attaches uprobes corresponding to enabled USDT probes
// The module given must be the module containing the enabled probes
func (c *Context) AttachUprobes(module *bcc.Module) error {
	// We lock the mutex because we're about to work with the global uprobes array
	uprobeMu.Lock()
	defer func() { uprobes = []uprobeCbArg{} }()
	defer uprobeMu.Unlock()
	C.bcc_usdt_foreach_uprobe(c.context, (C.bcc_usdt_uprobe_cb)(unsafe.Pointer(C.uprobe_cb_gateway)))
	for _, probe := range uprobes {
		fd, err := module.LoadUprobe(probe.fnName)
		if err != nil {
			return fmt.Errorf("Loading uprobe %s failed: %w", probe.fnName, err)
		}
		err = module.AttachUprobeByAddr(probe.path, probe.addr, fd, probe.pid)
		if err != nil {
			return fmt.Errorf("Attaching uprobe %s failed: %w", probe.fnName, err)
		}
	}
	return nil
}
