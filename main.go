package main

import (
	"debug/pe"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"

	mappe "github.com/egebalci/mappe/pkg"
)

var verbose *bool

func main() {

	banner()

	scrape := flag.Bool("s", false, "Scrape PE headers.")
	verbose = flag.Bool("v", false, "Verbose output mode.")
	ignore := flag.Bool("ignore", false, "Ignore integrity check errors.")
	flag.Parse()

	if len(os.Args) == 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Get the absolute path of the file
	abs, err := filepath.Abs(flag.Args()[len(flag.Args())-1])
	pError(err)
	file, err := pe.Open(abs)
	pError(err)
	printVerbose("Valid \"PE\" signature.", "+")
	rawFile, err2 := ioutil.ReadFile(abs)
	pError(err2)

	opt := mappe.UnifyOptionalHeader(file)

	printVerbose("File Size: "+strconv.Itoa(len(rawFile))+" byte", "*")
	printVerbose("Machine:"+fmt.Sprintf(" 0x%X", uint64(file.FileHeader.Machine)), "*")
	printVerbose("Magic:"+fmt.Sprintf(" 0x%X", uint64(opt.Magic)), "*")
	printVerbose("Subsystem:"+fmt.Sprintf(" 0x%X", uint64(opt.Subsystem)), "*")
	if opt.CheckSum != 0x00 {
		printVerbose("Checksum:"+fmt.Sprintf(" 0x%X", uint64(opt.CheckSum)), "*")
	}
	printVerbose("Image Base:"+fmt.Sprintf(" 0x%X", uint64(opt.ImageBase)), "*")
	printVerbose("Address Of Entry:"+fmt.Sprintf(" 0x%X", uint64(opt.AddressOfEntryPoint)), "*")
	printVerbose("Size Of Headers:"+fmt.Sprintf(" 0x%X", uint64(opt.SizeOfHeaders)), "*")
	printVerbose("Size Of Image:"+fmt.Sprintf(" 0x%X", uint64(opt.SizeOfImage)), "*")
	printVerbose("Export Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[0].VirtualAddress)+opt.ImageBase), "*")
	printVerbose("Import Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[1].VirtualAddress)+opt.ImageBase), "*")
	printVerbose("Base Relocation Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[5].VirtualAddress)+opt.ImageBase), "*")
	printVerbose("Import Address Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[12].VirtualAddress)+opt.ImageBase), "*")

	Map, err := mappe.CreateFileMapping(abs)
	pError(err)
	printVerbose("File mapping completed !", "+")
	printVerbose("Starting integrity checks...", "*")
	err = mappe.PerformIntegrityChecks(abs, Map)
	if !*ignore && err != nil {
		pError(err)
	}
	printVerbose("Integrity valid.", "+")
	mapFile, err := os.Create(abs + ".map")
	pError(err)
	defer mapFile.Close()
	if *scrape {
		printVerbose("Scraping file headers...", "*")
		mapFile.Write(mappe.Scrape(Map))
	} else {
		mapFile.Write(Map)
	}

	fmt.Println("[+] File maped into -> " + abs + ".map")
}

func pError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func printVerbose(str string, status string) {

	if *verbose {
		switch status {
		case "*":
			fmt.Println("[*] " + str)
		case "+":
			fmt.Println("[+] " + str)
		case "-":
			fmt.Println("[-] " + str)
		case "!":
			fmt.Println("[!] " + str)
		case "":
			fmt.Println(str)
		}
	}
}
func banner() {

	var banner = `
                      _____________________
   _____ _____  ______\______   \_   _____/
  /     \\__  \ \____ \|     ___/|    __)_ 
 |  Y Y  \/ __ \|  |_> >    |    |        \
 |__|_|  (____  /   __/|____|   /_______  /
       \/     \/|__|                    \/ 
Author: Ege Balcı
Source: github.com/egebalci/mape
`
	fmt.Println(banner)
}
