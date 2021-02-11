package internal

/*
#include <stdint.h>
#include <stdio.h>
#cgo CFLAGS: -I/usr/include/bcc/compat
#cgo LDFLAGS: -lbcc
#include <bcc/bcc_usdt.h>

void uprobe_cb_gateway (const char *path, const char *fn_name, uint64_t addr, int pid) {
	void uprobeCb(const char *path, const char *fn_name, uint64_t addr, int pid);
	uprobeCb(path, fn_name, addr, pid);
}

void probe_cb(struct bcc_usdt *probe) {
	printf("Found probe: %s %s %s\n", probe->provider, probe->name, probe->bin_path);
}
*/
import "C"
