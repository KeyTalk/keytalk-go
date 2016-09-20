// +build darwin

package hwsig

import "syscall"

var (
	_ = register(ComponentOsXUDID, func() (string, error) {
		return "", nil
	})

	_ = register(ComponentOsXBundleIdentifier, func() (string, error) {
		return "", nil
	})

	_ = register(ComponentOsXHardwareModel, func() (string, error) {
		return syscall.Sysctl("hw.model")
	})

	_ = register(ComponentOsXMacAddress, componentMacAddress)

	_ = register(ComponentOsXCpuInformation, func() (string, error) {
		return syscall.Sysctl("machdep.cpu.brand_string")
	})

	_ = register(ComponentOsXSerialNumber, func() (string, error) {
		return "", nil
	})
)
