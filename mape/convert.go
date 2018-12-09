package mape

import (
	"debug/pe"
)

// ConvertOptionalHeader stores a given
// 32 bit OptionalHeader struct inside a 64 bit OptionalHeader
func ConvertOptionalHeader(file *pe.File) OptionalHeader {

	var opt OptionalHeader

	if file.Machine == 0x8664 {
		opt.Magic = file.OptionalHeader.(*pe.OptionalHeader64).Magic
		opt.MajorLinkerVersion = file.OptionalHeader.(*pe.OptionalHeader64).MajorLinkerVersion
		opt.MinorLinkerVersion = file.OptionalHeader.(*pe.OptionalHeader64).MinorLinkerVersion
		opt.SizeOfCode = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfCode
		opt.SizeOfInitializedData = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfInitializedData
		opt.SizeOfUninitializedData = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfUninitializedData
		opt.AddressOfEntryPoint = file.OptionalHeader.(*pe.OptionalHeader64).AddressOfEntryPoint
		opt.BaseOfCode = file.OptionalHeader.(*pe.OptionalHeader64).BaseOfCode
		opt.ImageBase = file.OptionalHeader.(*pe.OptionalHeader64).ImageBase
		opt.SectionAlignment = file.OptionalHeader.(*pe.OptionalHeader64).SectionAlignment
		opt.FileAlignment = file.OptionalHeader.(*pe.OptionalHeader64).FileAlignment
		opt.MajorOperatingSystemVersion = file.OptionalHeader.(*pe.OptionalHeader64).MajorOperatingSystemVersion
		opt.MinorOperatingSystemVersion = file.OptionalHeader.(*pe.OptionalHeader64).MinorOperatingSystemVersion
		opt.MajorImageVersion = file.OptionalHeader.(*pe.OptionalHeader64).MajorImageVersion
		opt.MinorImageVersion = file.OptionalHeader.(*pe.OptionalHeader64).MinorImageVersion
		opt.MajorSubsystemVersion = file.OptionalHeader.(*pe.OptionalHeader64).MajorSubsystemVersion
		opt.MinorSubsystemVersion = file.OptionalHeader.(*pe.OptionalHeader64).MinorSubsystemVersion
		opt.Win32VersionValue = file.OptionalHeader.(*pe.OptionalHeader64).Win32VersionValue
		opt.SizeOfImage = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfImage
		opt.SizeOfHeaders = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeaders
		opt.CheckSum = file.OptionalHeader.(*pe.OptionalHeader64).CheckSum
		opt.Subsystem = file.OptionalHeader.(*pe.OptionalHeader64).Subsystem
		opt.DllCharacteristics = file.OptionalHeader.(*pe.OptionalHeader64).DllCharacteristics
		opt.SizeOfStackReserve = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfStackReserve
		opt.SizeOfStackCommit = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfStackCommit
		opt.SizeOfHeapReserve = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeapReserve
		opt.SizeOfHeapCommit = file.OptionalHeader.(*pe.OptionalHeader64).SizeOfHeapCommit
		opt.LoaderFlags = file.OptionalHeader.(*pe.OptionalHeader64).LoaderFlags
		opt.NumberOfRvaAndSizes = file.OptionalHeader.(*pe.OptionalHeader64).NumberOfRvaAndSizes

		for i, j := range file.OptionalHeader.(*pe.OptionalHeader32).DataDirectory {
			opt.DataDirectory[i].VirtualAddress = j.VirtualAddress
			opt.DataDirectory[i].Size = j.Size
		}

	} else if file.Machine == 0x14C {
		opt.Magic = file.OptionalHeader.(*pe.OptionalHeader32).Magic
		opt.MajorLinkerVersion = file.OptionalHeader.(*pe.OptionalHeader32).MajorLinkerVersion
		opt.MinorLinkerVersion = file.OptionalHeader.(*pe.OptionalHeader32).MinorLinkerVersion
		opt.SizeOfCode = file.OptionalHeader.(*pe.OptionalHeader32).SizeOfCode
		opt.SizeOfInitializedData = file.OptionalHeader.(*pe.OptionalHeader32).SizeOfInitializedData
		opt.SizeOfUninitializedData = file.OptionalHeader.(*pe.OptionalHeader32).SizeOfUninitializedData
		opt.AddressOfEntryPoint = file.OptionalHeader.(*pe.OptionalHeader32).AddressOfEntryPoint
		opt.BaseOfCode = file.OptionalHeader.(*pe.OptionalHeader32).BaseOfCode
		opt.ImageBase = uint64(file.OptionalHeader.(*pe.OptionalHeader32).ImageBase)
		opt.SectionAlignment = file.OptionalHeader.(*pe.OptionalHeader32).SectionAlignment
		opt.FileAlignment = file.OptionalHeader.(*pe.OptionalHeader32).FileAlignment
		opt.MajorOperatingSystemVersion = file.OptionalHeader.(*pe.OptionalHeader32).MajorOperatingSystemVersion
		opt.MinorOperatingSystemVersion = file.OptionalHeader.(*pe.OptionalHeader32).MinorOperatingSystemVersion
		opt.MajorImageVersion = file.OptionalHeader.(*pe.OptionalHeader32).MajorImageVersion
		opt.MinorImageVersion = file.OptionalHeader.(*pe.OptionalHeader32).MinorImageVersion
		opt.MajorSubsystemVersion = file.OptionalHeader.(*pe.OptionalHeader32).MajorSubsystemVersion
		opt.MinorSubsystemVersion = file.OptionalHeader.(*pe.OptionalHeader32).MinorSubsystemVersion
		opt.Win32VersionValue = file.OptionalHeader.(*pe.OptionalHeader32).Win32VersionValue
		opt.SizeOfImage = file.OptionalHeader.(*pe.OptionalHeader32).SizeOfImage
		opt.SizeOfHeaders = file.OptionalHeader.(*pe.OptionalHeader32).SizeOfHeaders
		opt.CheckSum = file.OptionalHeader.(*pe.OptionalHeader32).CheckSum
		opt.Subsystem = file.OptionalHeader.(*pe.OptionalHeader32).Subsystem
		opt.DllCharacteristics = file.OptionalHeader.(*pe.OptionalHeader32).DllCharacteristics
		opt.SizeOfStackReserve = uint64(file.OptionalHeader.(*pe.OptionalHeader32).SizeOfStackReserve)
		opt.SizeOfStackCommit = uint64(file.OptionalHeader.(*pe.OptionalHeader32).SizeOfStackCommit)
		opt.SizeOfHeapReserve = uint64(file.OptionalHeader.(*pe.OptionalHeader32).SizeOfHeapReserve)
		opt.SizeOfHeapCommit = uint64(file.OptionalHeader.(*pe.OptionalHeader32).SizeOfHeapCommit)
		opt.LoaderFlags = file.OptionalHeader.(*pe.OptionalHeader32).LoaderFlags
		opt.NumberOfRvaAndSizes = file.OptionalHeader.(*pe.OptionalHeader32).NumberOfRvaAndSizes

		for i, j := range file.OptionalHeader.(*pe.OptionalHeader64).DataDirectory {
			opt.DataDirectory[i].VirtualAddress = j.VirtualAddress
			opt.DataDirectory[i].Size = j.Size
		}
	}

	return opt

}
