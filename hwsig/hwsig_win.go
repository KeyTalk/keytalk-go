// +build windows

package hwsig

import (
	"bytes"
	"fmt"
	"os/user"

	wmi "github.com/StackExchange/wmi"
	glob "github.com/ryanuber/go-glob"
	registry "golang.org/x/sys/windows/registry"

	"encoding/binary"
	"syscall"
	"unsafe"

	"github.com/dutchcoders/setupapi"
)

const GENERIC_READ uint32 = 0x80000000
const OPEN_EXISTING uint32 = 0x3
const FILE_FLAG_OPEN_REPARSE_POINT uint32 = 0x00200000
const FILE_FLAG_BACKUP_SEMANTICS uint32 = 0x02000000

const (
	FILE_DEVICE_BEEP                = 0x00000001
	FILE_DEVICE_CD_ROM              = 0x00000002
	FILE_DEVICE_CD_ROM_FILE_SYSTEM  = 0x00000003
	FILE_DEVICE_CONTROLLER          = 0x00000004
	FILE_DEVICE_DATALINK            = 0x00000005
	FILE_DEVICE_DFS                 = 0x00000006
	FILE_DEVICE_DISK                = 0x00000007
	FILE_DEVICE_DISK_FILE_SYSTEM    = 0x00000008
	FILE_DEVICE_FILE_SYSTEM         = 0x00000009
	FILE_DEVICE_INPORT_PORT         = 0x0000000a
	FILE_DEVICE_KEYBOARD            = 0x0000000b
	FILE_DEVICE_MAILSLOT            = 0x0000000c
	FILE_DEVICE_MIDI_IN             = 0x0000000d
	FILE_DEVICE_MIDI_OUT            = 0x0000000e
	FILE_DEVICE_MOUSE               = 0x0000000f
	FILE_DEVICE_MULTI_UNC_PROVIDER  = 0x00000010
	FILE_DEVICE_NAMED_PIPE          = 0x00000011
	FILE_DEVICE_NETWORK             = 0x00000012
	FILE_DEVICE_NETWORK_BROWSER     = 0x00000013
	FILE_DEVICE_NETWORK_FILE_SYSTEM = 0x00000014
	FILE_DEVICE_NULL                = 0x00000015
	FILE_DEVICE_PARALLEL_PORT       = 0x00000016
	FILE_DEVICE_PHYSICAL_NETCARD    = 0x00000017
	FILE_DEVICE_PRINTER             = 0x00000018
	FILE_DEVICE_SCANNER             = 0x00000019
	FILE_DEVICE_SERIAL_MOUSE_PORT   = 0x0000001a
	FILE_DEVICE_SERIAL_PORT         = 0x0000001b
	FILE_DEVICE_SCREEN              = 0x0000001c
	FILE_DEVICE_SOUND               = 0x0000001d
	FILE_DEVICE_STREAMS             = 0x0000001e
	FILE_DEVICE_TAPE                = 0x0000001f
	FILE_DEVICE_TAPE_FILE_SYSTEM    = 0x00000020
	FILE_DEVICE_TRANSPORT           = 0x00000021
	FILE_DEVICE_UNKNOWN             = 0x00000022
	FILE_DEVICE_VIDEO               = 0x00000023
	FILE_DEVICE_VIRTUAL_DISK        = 0x00000024
	FILE_DEVICE_WAVE_IN             = 0x00000025
	FILE_DEVICE_WAVE_OUT            = 0x00000026
	FILE_DEVICE_8042_PORT           = 0x00000027
	FILE_DEVICE_NETWORK_REDIRECTOR  = 0x00000028
	FILE_DEVICE_BATTERY             = 0x00000029
	FILE_DEVICE_BUS_EXTENDER        = 0x0000002a
	FILE_DEVICE_MODEM               = 0x0000002b
	FILE_DEVICE_VDM                 = 0x0000002c
	FILE_DEVICE_MASS_STORAGE        = 0x0000002d
	FILE_DEVICE_SMB                 = 0x0000002e
	FILE_DEVICE_KS                  = 0x0000002f
	FILE_DEVICE_CHANGER             = 0x00000030
	FILE_DEVICE_SMARTCARD           = 0x00000031
	FILE_DEVICE_ACPI                = 0x00000032
	FILE_DEVICE_DVD                 = 0x00000033
	FILE_DEVICE_FULLSCREEN_VIDEO    = 0x00000034
	FILE_DEVICE_DFS_FILE_SYSTEM     = 0x00000035
	FILE_DEVICE_DFS_VOLUME          = 0x00000036
	FILE_DEVICE_SERENUM             = 0x00000037
	FILE_DEVICE_TERMSRV             = 0x00000038
	FILE_DEVICE_KSEC                = 0x00000039
	FILE_DEVICE_FIPS                = 0x0000003A
	FILE_DEVICE_INFINIBAND          = 0x0000003B
	IOCTL_DISK_BASE                 = FILE_DEVICE_DISK
	FILE_ANY_ACCESS                 = 0
	FILE_READ_ACCESS                = 0x0001
	FILE_WRITE_ACCESS               = 0x0002
	FILE_SPECIAL_ACCESS             = FILE_ANY_ACCESS
	METHOD_BUFFERED                 = 0
	METHOD_IN_DIRECT                = 1
	METHOD_OUT_DIRECT               = 2
	METHOD_NEITHER                  = 3
)

var (
	SMART_GET_VERSION    uint32 = CTL_CODE(IOCTL_DISK_BASE, 0x0020, METHOD_BUFFERED, FILE_READ_ACCESS)
	SMART_RCV_DRIVE_DATA uint32 = CTL_CODE(IOCTL_DISK_BASE, 0x0022, METHOD_BUFFERED, FILE_READ_ACCESS|FILE_WRITE_ACCESS)
)

var (
	kernel32, _             = syscall.LoadLibrary("kernel32.dll")
	globalMemoryStatusEx, _ = syscall.GetProcAddress(kernel32, "GlobalMemoryStatusEx")
)

type GetVersionInParam struct {
	bVersion      byte
	bRevision     byte
	bReserved     byte
	bIDEDeviceMap byte
	fCapabilities uint64
	dwReserved    [4]uint64
}

func CTL_CODE(deviceType, function, method, access uint32) uint32 {
	return ((deviceType) << 16) | ((access) << 14) | ((function) << 2) | (method)
}

var (
	_ = register(ComponentPredefined, func() (string, error) { return "000000000000", nil })

	_ = register(ComponentWindowsHddSerial, func() (string, error) {
		// this signature needs administrator rights on Windows, and is useless.
		path := fmt.Sprintf("\\\\.\\PhysicalDrive%d", 0)

		fd, err := syscall.CreateFile(syscall.StringToUTF16Ptr(path), GENERIC_READ, 0, nil, OPEN_EXISTING,
			FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return "", err
		}

		defer syscall.CloseHandle(fd)

		fmt.Println("ComponentWindowsHddSerial")

		//rddbuf := GetVersionInParam{}

		rddbuf := make([]byte, 44) //unsafe.Sizeof(GetVersionInParam))
		var bytesReturned uint32
		err = syscall.DeviceIoControl(fd, SMART_GET_VERSION, nil, 0, &rddbuf[0], uint32(44), &bytesReturned, nil)
		if err != nil {
			return "", err
		}

		fmt.Println(rddbuf)

		/*

			            void ReadPhysicalDriveInNTUsingSmart (string& anHddSerial, string& anHddModel)
			            {
			                int drive = 0;
			                HANDLE hPhysicalDriveIOCTL = 0;

			                //  Try to get a handle to PhysicalDrive IOCTL
			                char driveName [256] = {};
			                sprintf (driveName, "\\\\.\\PhysicalDrive%d", drive);

			                //  Windows NT, Windows 2000, Windows Server 2003, Vista
			                hPhysicalDriveIOCTL = ::CreateFile (driveName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE
			                if (hPhysicalDriveIOCTL == INVALID_HANDLE_VALUE)
			                    TA_THROW_MSG(std::runtime_error, boost::format("Unable to open physical drive %s, error code: 0x%lX") % driveName %
			                GETVERSIONINPARAMS GetVersionParams = {0};
			                DWORD cbBytesReturned = 0;
			                if (!::DeviceIoControl (hPhysicalDriveIOCTL, SMART_GET_VERSION, NULL, 0, &GetVersionParams, sizeof (GETVERSIONINPARAMS)
			                {
			                    int myError = ::GetLastError();
			                    ::CloseHandle(hPhysicalDriveIOCTL);
			                    TA_THROW_MSG(std::runtime_error, boost::format("DeviceIoControl(SMART_GET_VERSION) failed for physical drive %s, er
			                }
			                ULONG CommandSize = sizeof(SENDCMDINPARAMS) + IDENTIFY_BUFFER_SIZE;
			                ta::ScopedResource<PSENDCMDINPARAMS> Command((PSENDCMDINPARAMS)malloc(CommandSize), free);
			                // Retrieve the IDENTIFY data
			#define ID_CMD          0xEC            // Returns ID sector for ATA
			                Command -> irDriveRegs.bCommandReg = ID_CMD;
			                DWORD BytesReturned = 0;
			                if (!::DeviceIoControl (hPhysicalDriveIOCTL, SMART_RCV_DRIVE_DATA, Command, sizeof(SENDCMDINPARAMS), Command, CommandSi
			                {
			                    int myError = ::GetLastError();
			                    ::CloseHandle(hPhysicalDriveIOCTL);
			                    TA_THROW_MSG(std::runtime_error, boost::format("DeviceIoControl(SMART_RCV_DRIVE_DATA) failed for physical drive %s,
			                }
			                DWORD diskdata [256] = {};
			                USHORT* pIdSector = (USHORT*)(PIDENTIFY_DATA) (Command -> bBuffer);
			                for (int ijk = 0; ijk < 256; ijk++)
			                    diskdata [ijk] = pIdSector [ijk];

			                setHddInfo (drive, diskdata, anHddSerial, anHddModel);
			                ::CloseHandle (hPhysicalDriveIOCTL);
			            }
		*/

		return "00000000000000000001", nil
	}) // IDE, SCSI

	_ = register(ComponentWindowsNicMac, componentMacAddress)

	// TODO(nl5887): implement properly
	_ = register(ComponentWindowsHdd, getComponentWindowsHDD)

	_ = register(ComponentWindowsNic, getDeviceInfo("net", "PCI\\*", ""))
	_ = register(ComponentWindowsHdc, getDeviceInfo("hdc", "PCI\\*", ""))
	_ = register(ComponentWindowsUsbHub, getDeviceInfo("USB", "USB\\ROOT_HUB*", ""))
	_ = register(ComponentWindowsDisplayAdapter, getDeviceInfo("Display", "*", ""))

	_ = register(ComponentWindowsMemory, getComponentWindowsMemorySize)

	_ = register(ComponentWindowsCPU, getDeviceInfo("Processor", "*", ""))
	_ = register(ComponentWindowsIC, getDeviceInfo("System", "ACPI\\PNP0000*", "000\\0000\\00000"))
	_ = register(ComponentWindowsSysTimer, getDeviceInfo("System", "ACPI\\PNP0100*", ""))
	_ = register(ComponentWindowsDMA, getDeviceInfo("System", "ACPI\\PNP0200*", ""))
	_ = register(ComponentWindowsSysSpeaker, getDeviceInfo("System", "ACPI\\PNP0800*", ""))

	_ = register(ComponentWindowsOsRegisteredOwner, getComponentWindowsRegisteredOwner)
	_ = register(ComponentWindowsOsProductId, getComponentWindowsProductId)
	_ = register(ComponentWindowsUserSID, getComponentWindowsUserSID)
	_ = register(ComponentWindowsSerial, getComponentWindowsBiosSerialNumber)
)

func getComponentWindowsHDD() (string, error) {
	s, err := getDeviceInfo("DiskDrive", "IDE\\*", "")()
	if err != nil {
		return "", err
	}

	s2, err := getDeviceInfo("DiskDrive", "SCSI\\*", "")()
	if err != nil {
		return "", err
	}

	return s + s2, nil
}

func getComponentWindowsRegisteredOwner() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	s, _, err := k.GetStringValue("RegisteredOwner")
	if err != nil {
		return "", err
	}

	return s, nil
}

func getComponentWindowsProductId() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	s, _, err := k.GetStringValue("ProductId")
	if err != nil {
		return "", err
	}

	return s, nil
}

type Win32_BIOS struct {
	SerialNumber string
}

func getComponentWindowsBiosSerialNumber() (string, error) {
	var dst []Win32_BIOS
	q := wmi.CreateQuery(&dst, "")
	err := wmi.Query(q, &dst)
	if err != nil {
		return "", err
	}

	if len(dst) == 0 {
		return "", fmt.Errorf("No response")
	}

	return dst[0].SerialNumber, nil
}

func getComponentWindowsUserSID() (string, error) {
	if u, err := user.Current(); err != nil {
		return "", err
	} else {
		return u.Uid, nil
	}
}

func getComponentWindowsMemorySize() (string, error) {
	var memoryStatusEx [64]byte
	binary.LittleEndian.PutUint32(memoryStatusEx[:], 64)
	p := uintptr(unsafe.Pointer(&memoryStatusEx[0]))

	ret, _, callErr := syscall.Syscall(uintptr(globalMemoryStatusEx), 1, p, 0, 0)
	if ret == 0 {
		return "", callErr
	}

	return fmt.Sprintf("%d", binary.LittleEndian.Uint64(memoryStatusEx[8:])), nil
}

func getDeviceInfo(ClassName string, filter string, def string) func() (string, error) {
	return func() (string, error) {
		guids, err := setupapi.SetupDiClassGuidsFromNameEx(ClassName, "")
		if err != nil {
			return "", err
		}

		di, err := setupapi.SetupDiGetClassDevsEx(guids[0], "", 0, setupapi.Present, 0, "", 0)
		if err != nil {
			return "", err
		}

		buff := bytes.Buffer{}

		i := uint32(0)
		for {
			did, err := di.EnumDeviceInfo(i)
			if err != nil {
				// return "", err
				break
			}

			id, err := did.InstanceID()
			if err != nil {
				break
			}

			i++

			if !glob.Glob(filter, id) {
				continue
			}

			buff.WriteString(id)
		}

		if buff.Len() == 0 {
			return def, nil
		}

		return buff.String(), nil
	}
}

func Description() string {
	return fmt.Sprintf("Windows")
}
