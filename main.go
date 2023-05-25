package main

import (
	// "bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

// Flags
var hFlag = flag.Bool("h", false, "Display ELF header")

// ELF64 header structure
type ELF64Header struct {
	Magic                   [4]uint8
	Class                   uint8
	Data                    uint8
	Version                 uint8
	OSABI                   uint8
	ABIVersion              uint8
	Pad                     [7]uint8
	Type                    uint16
	Machine                 uint16
	EVersion                uint32
	Entry                   uint64
	ProgramHeaderOffset     uint64
	SectionHeaderOffset     uint64
	Flags                   uint32
	ELFHeaderSize           uint16
	ProgramHeaderEntrySize  uint16
	ProgramHeaderEntryCount uint16
	SectionHeaderEntrySize  uint16
	SectionHeaderEntryCount uint16
	SectionNameEntryIndex   uint16
}

func main() {
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("No file provided.")
		os.Exit(1)
	}

	f, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}
	defer f.Close()

	elfHeader := new(ELF64Header)

	err = binary.Read(f, binary.LittleEndian, elfHeader)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		os.Exit(1)
	}

	if *hFlag {
		printHeader(elfHeader)
	}
}

func printHeader(elfHeader *ELF64Header) {
	fmt.Println("ELF Header:")
	fmt.Printf("Magic:  %v\n", elfHeader.Magic)
	fmt.Printf("Class:  %v\n", elfHeader.Class)
	fmt.Printf("Data:   %v\n", elfHeader.Data)
	fmt.Printf("Version: %v\n", elfHeader.Version)
	fmt.Printf("OS/ABI: %v\n", elfHeader.OSABI)
	fmt.Printf("ABI Version: %v\n", elfHeader.ABIVersion)
	fmt.Printf("Type: %v\n", elfHeader.Type)
	fmt.Printf("Machine: %v\n", elfHeader.Machine)
	fmt.Printf("Entry: 0x%x\n", elfHeader.Entry)
	fmt.Printf("Program Header Offset: 0x%x\n", elfHeader.ProgramHeaderOffset)
	fmt.Printf("Section Header Offset: 0x%x\n", elfHeader.SectionHeaderOffset)
	fmt.Printf("Flags: 0x%x\n", elfHeader.Flags)
	fmt.Printf("ELF Header Size: %v\n", elfHeader.ELFHeaderSize)
	fmt.Printf("Program Header Entry Size: %v\n", elfHeader.ProgramHeaderEntrySize)
	fmt.Printf("Program Header Entry Count: %v\n", elfHeader.ProgramHeaderEntryCount)
	fmt.Printf("Section Header Entry Size: %v\n", elfHeader.SectionHeaderEntrySize)
	fmt.Printf("Section Header Entry Count: %v\n", elfHeader.SectionHeaderEntryCount)
	fmt.Printf("Section Name Entry Index: %v\n", elfHeader.SectionNameEntryIndex)
}
