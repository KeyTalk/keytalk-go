// +build darwin

package hwsig

import "testing"

func TestXxx(t *testing.T) {
	if _, err := componentMap[ComponentOsXHardwareModel](); err != nil {
		t.Error(err)
	}
	if _, err := componentMap[ComponentOsXCpuInformation](); err != nil {
		t.Error(err)
	}
	if _, err := componentMap[ComponentOsXMacAddress](); err != nil {
		t.Error(err)
	}
}
