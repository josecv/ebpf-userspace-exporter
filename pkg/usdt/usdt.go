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
	context unsafe.Pointer
	pid     int
	closed  bool
}

// NewContext returns a new usdt context for a given pid
func NewContext(pid int) (*Context, error) {
	context := C.bcc_usdt_new_frompid(C.int(pid), nil)
	if context == nil {
		return nil, fmt.Errorf("Unable to initialize USDT context")
	}
	return &Context{
		context: context,
		pid:     pid,
		closed:  false,
	}, nil
}

// Close closes a Context. After this it cannot be used.
func (u *Context) Close() {
	C.bcc_usdt_close(u.context)
	u.closed = true
}

// EnableProbe enables a probe
func (u *Context) EnableProbe(probe, fnName string) error {
	if u.closed {
		return fmt.Errorf("Context is closed")
	}
	parts := strings.Split(probe, ":")
	var ret int
	if len(parts) == 1 {
		ret = int(C.bcc_usdt_enable_fully_specified_probe(u.context, C.CString("python"), C.CString(probe), C.CString(fnName)))
	} else {
		return fmt.Errorf("Not implemented yet lol")
	}
	if ret != 0 {
		return fmt.Errorf("Failed to enable function %s for USDT probe %s; is the probe built into the target?", fnName, probe)
	}
	return nil
}

// CompileModule compiles a module from the text given, loads and attaches enabled uprobes, and returns the module.
// The caller is responsible for closing the module.
func (u *Context) CompileModule(text string, cflags []string) (*bcc.Module, error) {
	if u.closed {
		return nil, fmt.Errorf("Context is closed")
	}
	fullText := C.GoString(C.bcc_usdt_genargs(&u.context, C.int(1))) + text
	module := bcc.NewModule(fullText, cflags)
	if module == nil {
		return nil, fmt.Errorf("Could not compile module")
	}
	err := u.attachUprobes(module)
	if err != nil {
		module.Close()
		return nil, err
	}
	return module, nil
}

type uprobeCbArg struct {
	path   string
	fnName string
	addr   uint64
	pid    int
}

// AttachedUprobe represents a uprobe that has been attached to a running program
type AttachedUprobe struct {
	Addr uint64
	Pid  int
	Tag  string
}

var uprobes []uprobeCbArg
var uprobeMu sync.Mutex

//export uprobeCb
func uprobeCb(path, fnName *C.char, addr uint64, pid int) {
	uprobes = append(uprobes, uprobeCbArg{C.GoString(path), C.GoString(fnName), addr, pid})
}

func (u *Context) attachUprobes(module *bcc.Module) error {
	// We lock the mutex because we're about to work with the global uprobes array
	uprobeMu.Lock()
	defer func() { uprobes = []uprobeCbArg{} }()
	defer uprobeMu.Unlock()
	C.bcc_usdt_foreach_uprobe(u.context, (C.bcc_usdt_uprobe_cb)(unsafe.Pointer(C.uprobe_cb_gateway)))
	for _, probe := range uprobes {
		fmt.Printf("Probe is %s for path %s addr %d pid %d\n", probe.fnName, probe.path, probe.addr, probe.pid)
		fd, err := module.LoadUprobe(probe.fnName)
		if err != nil {
			return fmt.Errorf("Loading uprobe %s failed: %s", probe.fnName, err)
		}
		err = module.AttachUprobeByAddr(probe.path, probe.addr, fd, probe.pid)
		if err != nil {
			return fmt.Errorf("Attaching uprobe %s failed: %s", probe.fnName, err)
		}
	}
	return nil
}
