// +build darwin

package hwsig

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"syscall"

	"github.com/mitchellh/go-homedir"
)

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

	_ = register(ComponentOsXGenerated, func() (string, error) {
		if homedir, err := homedir.Dir(); err != nil {
			return "", err
		} else {

			filename := path.Join(homedir, "Library", "KeyTalk", "uuid")

			if _, err := os.Stat(filename); os.IsNotExist(err) {
				data := make([]byte, 256)
				if _, err := rand.Read(data); err != nil {
					return "", err
				}

				signature := fmt.Sprintf("%x", sha256.Sum256(data))

				err := ioutil.WriteFile(filename, []byte(signature), 0600)
				return signature, err
			} else if err != nil {
				return "", err
			} else if data, err := ioutil.ReadFile(filename); err != nil {
				return "", err
			} else {
				return string(data), nil
			}
		}
	})
)

func Description() string {
	version, _ := syscall.Sysctl("kern.osrelease")
	// revision, _ := syscall.Sysctl("kern.osrevision")
	// hostname, _ := syscall.Sysctl("kern.hostname")
	return fmt.Sprintf("MacOS %s", version)
}
