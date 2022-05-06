package mappe

import (
	"debug/pe"
	"io/ioutil"
	"path/filepath"
)

// UnifiedOptionalHeader = pe.OptionalHeader64
type UnifiedOptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64 // uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64 // uint32
	SizeOfStackCommit           uint64 // uint32
	SizeOfHeapReserve           uint64 // uint32
	SizeOfHeapCommit            uint64 // uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]DataDirectory
}

// DataDirectory = pe.DataDirectory
type DataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// PEMap holds the PE file for processing
type PEMap struct {
	Name string
	PE   *pe.File
	Raw  []byte
}

// Open a new PEMap
func Open(fileName string) (*PEMap, error) {

	abs, err := filepath.Abs(fileName)
	if err != nil {
		return nil, err
	}

	new := PEMap{Name: abs}
	peFile, err := pe.Open(fileName)
	defer peFile.Close()
	if err != nil {
		return nil, err
	}
	new.PE = peFile

	rawFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	new.Raw = rawFile
	return &new, nil
}
