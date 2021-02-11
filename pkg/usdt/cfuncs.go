package usdt

/*
#include <stdint.h>

void uprobe_cb_gateway (const char *path, const char *fn_name, uint64_t addr, int pid) {
	void uprobeCb(const char *path, const char *fn_name, uint64_t addr, int pid);
	uprobeCb(path, fn_name, addr, pid);
}
*/
import "C"
