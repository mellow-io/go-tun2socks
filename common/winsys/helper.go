// +build windows

package winsys

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func CreateDisplayData(name, description string) (*FWPM_DISPLAY_DATA0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, err
	}

	return &FWPM_DISPLAY_DATA0{
		Name:        namePtr,
		Description: descriptionPtr,
	}, nil
}

func GetCurrentProcessAppID() (*FWP_BYTE_BLOB, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, err
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, err
	}

	var appID *FWP_BYTE_BLOB
	err = FwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, err
	}
	return appID, nil
}
