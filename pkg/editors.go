package mappe

import (
	"bytes"
	"debug/pe"
	"encoding/gob"
	"errors"
	"os"
	"strings"
)

// SetSection sets the given raw section contents as byte array as the named section
// Also fixes the section header accordingly
func (file PEMap) SetSection(sectionName string, newSectionData []byte) error {

	oldSectionData, err := file.PE.Section(sectionName).Data()
	oldSectionHeader := pe.SectionHeader32{
		VirtualSize:          file.PE.Section(sectionName).SectionHeader.VirtualSize,
		VirtualAddress:       file.PE.Section(sectionName).SectionHeader.VirtualAddress,
		SizeOfRawData:        file.PE.Section(sectionName).SectionHeader.Size,
		PointerToRawData:     file.PE.Section(sectionName).SectionHeader.Offset,
		PointerToRelocations: file.PE.Section(sectionName).SectionHeader.PointerToRelocations,
		PointerToLineNumbers: file.PE.Section(sectionName).SectionHeader.PointerToLineNumbers,
		NumberOfRelocations:  file.PE.Section(sectionName).SectionHeader.NumberOfRelocations,
		NumberOfLineNumbers:  file.PE.Section(sectionName).SectionHeader.NumberOfLineNumbers,
		Characteristics:      file.PE.Section(sectionName).SectionHeader.Characteristics,
	}

	for i, c := range file.PE.Section(sectionName).SectionHeader.Name {
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
	file.Raw = []byte(strings.ReplaceAll(string(file.Raw), string(oldSectionData), string(newSectionData)))

	// Adjust new section header sizes
	oldSectionHeader.SizeOfRawData += uint32(len(newSectionData) - len(oldSectionData))
	oldSectionHeader.VirtualSize += uint32(len(newSectionData) - len(oldSectionData))

	encoder = gob.NewEncoder(&newSectionHeaderData)
	err = encoder.Encode(oldSectionHeader)
	if err != nil {
		return err
	}

	if oldSectionHeaderData.Len() != newSectionHeaderData.Len() {
		return errors.New("section headers size increased")
	}

	// Replace section header data
	file.Raw = []byte(strings.ReplaceAll(string(file.Raw), string(oldSectionHeaderData.Bytes()), string(newSectionHeaderData.Bytes())))

	newFile, err := os.Open(file.Name)
	if err != nil {
		return err
	}

	_, err = newFile.Write(file.Raw)

	return err
}

// SetOptionalHeader sets a new optional header
func SetOptionalHeader(fileName string, newOPHeader interface{}) error {

	return nil
}
