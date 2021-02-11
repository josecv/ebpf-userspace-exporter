package internal

import (
	"fmt"
	"io/ioutil"
)

// Attach attaches
func Attach(pid int, probe, fnName, path string) error {
	code, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	usdt, err := NewUSDTContext(pid)
	if err != nil {
		return err
	}
	defer usdt.Close()
	err = usdt.AddProbe(probe, fnName, string(code))
	if err != nil {
		return err
	}
	err = usdt.EnableProbe(probe, fnName)
	if err != nil {
		return err
	}
	_, err = usdt.CompileModule()
	if err != nil {
		return err
	}
	fmt.Printf("its britney bitch\n")
	return nil
}
