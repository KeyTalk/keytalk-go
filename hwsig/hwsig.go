// Package hwsig creates hardware signatures
package hwsig

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"strings"
)

type Component uint32

const (
	ComponentPredefined Component = 0

	// range 1-100   reserved for Windows Desktop Client.
	ComponentWindowsHddSerial         Component = 1    // Primary HDD Serial defined by minimal i for which \\.\PhysicalDrive<i> or \\.\Scsi<i> is accessible
	ComponentWindowsNicMac                      = iota // Primary NIC MAC-address. Primary NIC is NIC listed first in the "Network Connections" folder-> Advanced menu -> Advanced settings list.
	ComponentWindowsHdd                                // HDDs Device Instance IDs. Only PCI IDE and SCSI HDDs are considered skipping hot-plugguble disks attached to USB or PCMCIA.
	ComponentWindowsNic                                // NICs Device Instance IDs. Only NICs attached to PCI are considered to avoid pluggable NICS e.g. USB.
	ComponentWindowsHdc                                // PCI IDE ATA/ATAPI controllers Device Instance IDs excluding hot-pluggable ones like e.g. PCMCIA.
	ComponentWindowsUsbHub                             // USB Root Hubs Device Instance IDs.
	ComponentWindowsDisplayAdapter                     // Display Adapters Device Instance IDs.
	ComponentWindowsMemory                             // Amount of physical memory.
	ComponentWindowsCPU                                // CPUs device instance IDs.
	ComponentWindowsIC                                 // Interrupt controller device instance ID.
	ComponentWindowsSysTimer                           // System timer device instance ID.
	ComponentWindowsDMA                                // DMA controller device instance ID.
	ComponentWindowsSysSpeaker                         // System speaker device instance ID.
	ComponentWindowsOsProductId                        // OS Product ID.
	ComponentWindowsOsRegisteredOwner                  // OS registered owner.
	ComponentWindowsUserSID                            // User Security Identifier.
	ComponentWindowsSerial                             // Serial number retrieved from BIOS

	// range 101-200 reserved for iOS mobile Client
	// range 201-300 reserved for Android mobile Client

	// Unique device Identifier, deprecated in iOS 5
	ComponentOsXUDID             Component = 501
	ComponentOsXBundleIdentifier           = iota
	ComponentOsXHardwareModel
	ComponentOsXMacAddress
	ComponentOsXCpuInformation
	ComponentOsXSerialNumber
	ComponentOsXSentinel
	ComponentOsXGenerated = 599

	ComponentLinuxHddSerial   Component = 601  // 601: Primary HDD Serial.
	ComponentLinuxNicMac                = iota // 602: Primary NIC MAC-address.
	ComponentLinuxCPUArch                      // 603: CPUs hardware architectures.
	ComponentLinuxCPUModel                     // 604: CPUs model
	ComponentLinuxOsProductId                  // 605: OS name.
	ComponentLinuxUserName                     // 606: User name.
	ComponentLinuxSerial                       // 607: Serial number read from BIOS. When BIOS is not available (e.g. on RaspberryPi) return CPU serial number
	ComponentLinuxSshPubKey                    // 608: SSH2 public keys of the host if available
)

func (c Component) String() string {
	switch c {
	}

	return fmt.Sprintf("%d", uint32(c))
}

type ComponentFn func() (string, error)

var componentMap = map[Component]ComponentFn{}

func register(component Component, fn ComponentFn) ComponentFn {
	componentMap[component] = fn
	return fn
}

// Calc calculates the signature for all registered components
func CalcAll() (string, error) {
	keys := []Component{}
	for k := range componentMap {
		keys = append(keys, k)
	}

	return Calc(keys)
}

// Calc calculates the signature for one or more components
func Calc(components []Component) (string, error) {
	h := sha256.New()

	for _, component := range components {
		if componentFn, ok := componentMap[component]; !ok {
			// ignore
		} else if val, err := componentFn(); err != nil {
			return "", err
		} else {
			h.Write([]byte(val))
		}
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func componentMacAddress() (string, error) {
	ifs, _ := net.Interfaces()

	for _, v := range ifs {
		h := v.HardwareAddr.String()
		if len(h) == 0 {
			continue
		}
		return strings.ToUpper(strings.Replace(h, ":", "", -1)), nil
	}

	return "", fmt.Errorf("No network interfaces found.")
}

func combine(components ...ComponentFn) (string, error) {
	var buffer bytes.Buffer
	for _, componentFunc := range components {
		if s, err := componentFunc(); err != nil {
			return "", err
		} else {
			buffer.WriteString(s)
		}
	}
	return buffer.String(), nil
}
