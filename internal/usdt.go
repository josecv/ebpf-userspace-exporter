package internal

import (
	"fmt"
	"github.com/josecv/gobpf/bcc"
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
void probe_cb(struct bcc_usdt *probe);
*/
import "C"

// USDTContext is the attached usdt context for a particular pid
type USDTContext struct {
	context unsafe.Pointer
	pid     int
	closed  bool
	probes  map[usdtProbe]string
	module  *bcc.Module
}

type usdtProbe struct {
	probe  string
	fnName string
}

type uprobeCbArg struct {
	path   string
	fnName string
	addr   uint64
	pid    int
}

var uprobes []uprobeCbArg
var uprobeMu sync.Mutex

// NewUSDTContext returns a new usdt context for a given pid
func NewUSDTContext(pid int) (*USDTContext, error) {
	context := C.bcc_usdt_new_frompid(C.int(pid), nil)
	if context == nil {
		return nil, fmt.Errorf("Unable to initialize USDT context")
	}
	return &USDTContext{
		context: context,
		pid:     pid,
		closed:  false,
		probes:  make(map[usdtProbe]string),
		module:  nil,
	}, nil
}

// Close closes a USDTContext. After this it cannot be used.
func (u *USDTContext) Close() {
	C.bcc_usdt_close(u.context)
	if u.module != nil {
		u.module.Close()
	}
	u.closed = true
}

// AddProbe adds a probe to the set of managed probes. Does not enable it
func (u *USDTContext) AddProbe(probe, fnName, text string) error {
	if u.closed {
		return fmt.Errorf("USDTContext is closed")
	}
	probeTuple := usdtProbe{probe: probe, fnName: fnName}
	if _, ok := u.probes[probeTuple]; ok {
		return fmt.Errorf("A function named %s has already been attached to probe %s", fnName, probe)
	}
	u.probes[probeTuple] = text
	return nil
}

// EnableProbe enables a probe
func (u *USDTContext) EnableProbe(probe, fnName string) error {
	if u.closed {
		return fmt.Errorf("USDTContext is closed")
	}
	C.bcc_usdt_foreach(u.context, (C.bcc_usdt_cb)(unsafe.Pointer(C.probe_cb)))
	parts := strings.Split(probe, ":")
	var ret int
	if len(parts) == 1 {
		ret = int(C.bcc_usdt_enable_fully_specified_probe(u.context, C.CString("python"), C.CString(probe), C.CString(fnName)))
	} else {
		return fmt.Errorf("Not implemented yet lol")
	}
	if ret != 0 {
		return fmt.Errorf("Failed to enable USDT probe %s; is the probe built into the pid?", probe)
	}
	return nil
}

// CompileModule compiles a bcc module from the probes in this context. The module will be closed on closing the context.
func (u *USDTContext) CompileModule() (*bcc.Module, error) {
	if u.closed {
		return nil, fmt.Errorf("USDTContext is closed")
	}
	if u.module != nil {
		return u.module, nil
	}
	fullText := ""
	for _, text := range u.probes {
		fullText += text
	}
	fullText = C.GoString(C.bcc_usdt_genargs(&u.context, C.int(1))) + fullText
	module := bcc.NewModule(fullText, []string{})
	if module == nil {
		return nil, fmt.Errorf("Could not compile module")
	}
	u.module = module
	if err := u.attachUprobes(); err != nil {
		module.Close()
		u.module = nil
		return nil, err
	}
	return u.module, nil
}

//export uprobeCb
func uprobeCb(path, fnName *C.char, addr uint64, pid int) {
	uprobes = append(uprobes, uprobeCbArg{C.GoString(path), C.GoString(fnName), addr, pid})
}

func (u *USDTContext) attachUprobes() error {
	// We lock the mutex because we're about to work with the global uprobes array
	uprobeMu.Lock()
	defer func() { uprobes = []uprobeCbArg{} }()
	defer uprobeMu.Unlock()
	C.bcc_usdt_foreach_uprobe(u.context, (C.bcc_usdt_uprobe_cb)(unsafe.Pointer(C.uprobe_cb_gateway)))
	for _, probe := range uprobes {
		fmt.Printf("Probe is %s for path %s addr %d pid %d\n", probe.fnName, probe.path, probe.addr, probe.pid)
		fd, err := u.module.LoadUprobe(probe.fnName)
		if err != nil {
			return nil
		}
		err = u.module.AttachUprobeByAddr(probe.path, probe.addr, fd, probe.pid)
		if err != nil {
			return err
		}
	}
	return nil
}
