package mappe

import (
	"bytes"
	"debug/pe"
	"encoding/gob"
	"io/ioutil"
	"strings"
)

// SetSection sets the given raw section contents as byte array as the named section
// Also fixes the section header accordingly
func SetSection(fileName string, sectionName string, newSectionData []byte) error {
	peFile, err := pe.Open(fileName)
	if err != nil {
		return err
	}

	rawFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}

	oldSectionData, err := peFile.Section(sectionName).Data()
	oldSectionHeader := pe.SectionHeader32{
		VirtualSize:          peFile.Section(sectionName).SectionHeader.VirtualSize,
		VirtualAddress:       peFile.Section(sectionName).SectionHeader.VirtualAddress,
		SizeOfRawData:        peFile.Section(sectionName).SectionHeader.Size,
		PointerToRawData:     peFile.Section(sectionName).SectionHeader.Offset,
		PointerToRelocations: peFile.Section(sectionName).SectionHeader.PointerToRelocations,
		PointerToLineNumbers: peFile.Section(sectionName).SectionHeader.PointerToLineNumbers,
		NumberOfRelocations:  peFile.Section(sectionName).SectionHeader.NumberOfRelocations,
		NumberOfLineNumbers:  peFile.Section(sectionName).SectionHeader.NumberOfLineNumbers,
		Characteristics:      peFile.Section(sectionName).SectionHeader.Characteristics,
	}

	for i, c := range peFile.Section(sectionName).SectionHeader.Name {
		oldSectionHeader.Name[i] = uint8(c)
	}

	var oldSectionHeaderData bytes.Buffer
	var newSectionHeaderData bytes.Buffer

	// Get raw old section header bytes
	encoder := gob.NewEncoder(&oldSectionHeaderData)
	err = encoder.Encode(oldSectionHeader)
	if err != nil {
		return err
	}

	// Replace section data
	rawFile = []byte(strings.ReplaceAll(string(rawFile), string(oldSectionData), string(newSectionData)))

	// Adjust new section header sizes
	oldSectionHeader.SizeOfRawData += uint32(len(newSectionData) - len(oldSectionData))
	oldSectionHeader.VirtualSize += uint32(len(newSectionData) - len(oldSectionData))

	encoder = gob.NewEncoder(&newSectionHeaderData)
	err = encoder.Encode(oldSectionHeader)
	if err != nil {
		return err
	}
	// Replace section header data
	rawFile = []byte(strings.ReplaceAll(string(rawFile), string(oldSectionHeaderData.Bytes()), string(newSectionHeaderData.Bytes())))

	return nil
}
