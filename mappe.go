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

	"./mape"
	//"github.com/egebalci/mappe/mape"
)

// ARGS tool arguments
type ARGS struct {
	scrape  bool
	verbose bool
	help    bool
	ignore  bool
}

var args ARGS

func main() {

	banner()

	flag.BoolVar(&args.scrape, "s", false, "Scrape PE headers.")
	flag.BoolVar(&args.verbose, "v", false, "Verbose output mode.")
	flag.BoolVar(&args.ignore, "ignore", false, "Ignore integrity check errors.")
	flag.BoolVar(&args.help, "h", false, "Display this message")
	flag.Parse()

	if len(os.Args) == 1 || args.help {
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Get the absolute path of the file
	abs, err := filepath.Abs(flag.Args()[len(flag.Args())-1])
	pError(err)
	file, err := pe.Open(abs)
	pError(err)
	verbose("Valid \"PE\" signature.", "+")
	rawFile, err2 := ioutil.ReadFile(abs)
	pError(err2)

	opt := mape.ConvertOptionalHeader(file)

	verbose("File Size: "+strconv.Itoa(len(rawFile))+" byte", "*")
	verbose("Machine:"+fmt.Sprintf(" 0x%X", uint64(file.FileHeader.Machine)), "*")
	verbose("Magic:"+fmt.Sprintf(" 0x%X", uint64(opt.Magic)), "*")
	verbose("Subsystem:"+fmt.Sprintf(" 0x%X", uint64(opt.Subsystem)), "*")
	if opt.CheckSum != 0x00 {
		verbose("Checksum:"+fmt.Sprintf(" 0x%X", uint64(opt.CheckSum)), "*")
	}
	verbose("Image Base:"+fmt.Sprintf(" 0x%X", uint64(opt.ImageBase)), "*")
	verbose("Address Of Entry:"+fmt.Sprintf(" 0x%X", uint64(opt.AddressOfEntryPoint)), "*")
	verbose("Size Of Headers:"+fmt.Sprintf(" 0x%X", uint64(opt.SizeOfHeaders)), "*")
	verbose("Size Of Image:"+fmt.Sprintf(" 0x%X", uint64(opt.SizeOfImage)), "*")
	verbose("Export Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[0].VirtualAddress)+opt.ImageBase), "*")
	verbose("Import Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[1].VirtualAddress)+opt.ImageBase), "*")
	verbose("Base Relocation Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[5].VirtualAddress)+opt.ImageBase), "*")
	verbose("Import Address Table:"+fmt.Sprintf(" 0x%X", uint64(opt.DataDirectory[12].VirtualAddress)+opt.ImageBase), "*")

	Map, err := mape.CreateFileMapping(abs)
	pError(err)
	verbose("File mapping completed !", "+")
	verbose("Starting integrity checks...", "*")
	err = mape.PerformIntegrityChecks(abs, Map)
	if !args.ignore && err != nil {
		pError(err)
	}
	verbose("Integrity valid.", "+")
	mapFile, err := os.Create(abs + ".map")
	pError(err)
	defer mapFile.Close()
	verbose("Scraping file headers...", "*")
	if args.scrape {
		mapFile.Write(mape.Scrape(Map))
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

func verbose(str string, status string) {

	if args.verbose {
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
Github: github.com/egebalci/mape
`
	fmt.Println(banner)
}
