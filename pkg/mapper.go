package mappe

import (
	"bytes"
	"errors"
)

// CreateFileMapping constructs the memory mapped image of given PE file.
func (file PEMap) CreateFileMapping() ([]byte, error) {

	opt := file.UnifyOptionalHeader()
	Map := bytes.Buffer{}
	offset := opt.ImageBase
	Map.Write(file.Raw[0:int(opt.SizeOfHeaders)])
	offset += uint64(opt.SizeOfHeaders)
	for _, sec := range file.PE.Sections {
		// Append null bytes if there is a gap between sections or PE header
		for offset < (uint64(sec.VirtualAddress) + opt.ImageBase) {
			Map.WriteString(string(0x00))
			offset++
		}
		// Map the section
		section, err := sec.Data()
		if err != nil {
			return nil, err
		}
		_, err = Map.Write(section)
		if err != nil {
			return nil, err
		}
		offset += uint64(sec.Size)
		// Append null bytes until reaching the end of the virtual address of the section
		for offset < (uint64(sec.VirtualAddress) + uint64(sec.VirtualSize) + opt.ImageBase) {
			Map.WriteString(string(0x00))
			offset++
		}

	}
	for (offset - opt.ImageBase) < uint64(opt.SizeOfImage) {
		Map.WriteString(string(0x00))
		offset++
	}
	return Map.Bytes(), nil
}

// PerformIntegrityChecks validates the integrity of the mapped PE file
func (file PEMap) PerformIntegrityChecks(memMap []byte) error {

	Map := bytes.Buffer{}
	_, err := Map.Write(memMap)
	if err != nil {
		return err
	}

	opt := file.UnifyOptionalHeader()
	report := ""
	if int(opt.SizeOfImage) != Map.Len() {
		report += "\t- Mapping size does not match the size of image header"
	}

	for _, j := range file.PE.Sections {
		for k := 0; k < int(j.Size); k++ {
			Buffer := Map.Bytes()
			if file.Raw[int(j.Offset)+k] != Buffer[int(j.VirtualAddress)+k] {
				report += "\t- Broken section alignment at" + j.Name
			}
		}

	}

	if report != "" {
		return errors.New("integrity checks failed: \n" + report)
	}
	return nil
}

// Scrape function removes the PE header from the mapped image
func Scrape(Map []byte) []byte {

	// if string(Map[:2]) == "MZ" {
	// 	verbose(hex.Dump(Map[:2]),0)
	// 	Map[0] = 0x00
	// 	Map[1] = 0x00
	// }

	// for i:=0; i<0x1000; i++ {
	// 	if string(Map[i:i+2]) == "PE" {
	// 		verbose(hex.Dump(Map[i:i+2]),0)
	// 		Map[i] = 0x00
	// 		Map[i+1] = 0x00
	// 	}
	// }

	for i := 0; i < 0x1000; i++ {
		if string(Map[i:i+39]) == "This program cannot be run in DOS mode." {
			for j := 0; j < 39; j++ {
				Map[i+j] = 0x00
			}
		}
	}

	for i := 66; i < 0x1000; i++ {
		if Map[i] == 0x2e && Map[i+1] < 0x7e && Map[i+1] > 0x21 {
			for j := 0; j < 7; j++ {
				Map[i+j] = 0x00
			}
		}
	}

	return Map
}
