package main

import (
	// "bytes"

	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

// Flags
var hFlag = flag.Bool("h", false, "Display ELF header")
var lFlag = flag.Bool("l", false, "Display the program header")
var SFlag = flag.Bool("S", false, "Display the section header")
var strdumpFlag = flag.String("string-dump", "", "dump the strings of section")

var (
	ELFMAG0      string // \x7f
	ELFMAG1      string // "E"
	ELFMAG2      string // "L"
	ELFMAG3      string // "F"
	EI_CLASS     string //b[4],0=ELFCLASSNONE, 1=ELFCLASS32, 2=ELFCLASS64
	EI_DATA      string //b[5],0=ELFDATANONE,1=ELFDATA2LSB,2=ELFDATA2MSB
	EI_VERSION   string
	EI_PAD       string
	ELF64        bool
	LittleEndian bool
)

var (
	debug_str, shstrtab, strtab Shdr64
)

type ELFHeader64 struct {
	e_ident     [16]byte //16 bytes
	e_type      uint16   //2 bytes
	e_machine   uint16   //2 bytes
	e_version   uint32   //4 bytes
	e_entry     uint64   //8 bytes
	e_phoff     uint64   //8 bytes
	e_shoff     uint64   //8 bytes
	e_flags     uint32   //4 bytes
	e_ehsize    uint16   //2 bytes
	e_phentsize uint16   //2 bytes
	e_phnum     uint16   //2 bytes
	e_shentsize uint16   //2 bytes
	e_shnum     uint16   //2 bytes
	e_shstrndx  uint16   //2 bytes
} //total 64 bytes

type Phdr64 struct {
	p_type   uint32 //4 bytes
	p_flags  uint32 //4 bytes
	p_offset uint64 //8 bytes
	p_vaddr  uint64 //8 bytes
	p_paddr  uint64 //8 bytes
	p_filesz uint64 //8 bytes
	p_memsz  uint64 //8 bytes
	p_align  uint64 //8 bytes
}

type Shdr64 struct {
	sh_name      uint32 //4 bytes
	sh_type      uint32 //4 bytes
	sh_flags     uint64 //8 bytes
	sh_addr      uint64 //8 bytes
	sh_offset    uint64 //8 bytes
	sh_size      uint64 //8 bytes
	sh_link      uint32 //4 bytes
	sh_info      uint32 //4 bytes
	sh_addralign uint64 //8 bytes
	sh_entsize   uint64 //8 bytes
	sh_name_str  string
} //total 64 bytes

func main() {
	flag.Parse()

	if len(flag.Args()) < 1 {
		fmt.Println("No file provided.")
		os.Exit(1)
	}
	filename := flag.Arg(0)
	f, err := os.Open(filename)
	if err != nil {
		fmt.Println("Error opening file:", err)
		os.Exit(1)
	}
	defer f.Close()

	_, _, elfHeader64 := isValidELF(filename)

	if err != nil {
		fmt.Println("binary.Read failed:", err)
		os.Exit(1)
	}

	if *hFlag {
		printHeader(elfHeader64)
	}

	if *lFlag {
		printProgramHeader(filename, elfHeader64)
	}

	if *SFlag {
		printSectionHeader(filename, elfHeader64)
	}

	if *strdumpFlag != "" {
		shdrs := getSectionsHeader(filename, elfHeader64)
		for _, shdr := range shdrs {
			if shdr.sh_name_str == *strdumpFlag {
				strs, _ := getSectionString(filename, shdr)
				for _, str := range strs {
					fmt.Printf("%s\n", str)
				}
			}
		}
	}
}

func isValidELF(fileName string) (bool, bool, ELFHeader64) {
	f, _ := os.Open(fileName)
	b := make([]byte, 64)
	bufr := bufio.NewReader(f)
	_, err := io.ReadFull(bufr, b)

	if err != nil {
		log.Fatal(err)
	}

	var elfHeader64 ELFHeader64

	if b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' {
		var index int
		for index = 0; index < 16; index++ {
			elfHeader64.e_ident[index] = b[index]
		}
		setEIClass(b[4])
		setEIData(b[5])
		elfHeader64.e_type = GetUINT16(b[16:18], LittleEndian)
		elfHeader64.e_machine = GetUINT16(b[18:20], LittleEndian)
		elfHeader64.e_version = GetUINT32(b[20:24], LittleEndian)
		elfHeader64.e_entry = GetUINT64(b[24:32], LittleEndian)
		elfHeader64.e_phoff = GetUINT64(b[32:40], LittleEndian)
		elfHeader64.e_shoff = GetUINT64(b[40:48], LittleEndian)
		elfHeader64.e_flags = GetUINT32(b[48:52], LittleEndian)
		elfHeader64.e_ehsize = GetUINT16(b[52:54], LittleEndian)
		elfHeader64.e_phentsize = GetUINT16(b[54:56], LittleEndian)
		elfHeader64.e_phnum = GetUINT16(b[56:58], LittleEndian)
		elfHeader64.e_shentsize = GetUINT16(b[58:60], LittleEndian)
		elfHeader64.e_shnum = GetUINT16(b[60:62], LittleEndian)
		elfHeader64.e_shstrndx = GetUINT16(b[62:64], LittleEndian)
		return true, true, elfHeader64
	}
	return false, false, elfHeader64
}

func setEIClass(b byte) {
	switch b {
	case 0:
		EI_CLASS = "ELFCLASSNONE" //无文件类型
		ELF64 = false
	case 1:
		EI_CLASS = "ELFCLASS32" //32位文件
		ELF64 = false
	case 2:
		EI_CLASS = "ELFCLASS64" //64位文件
		ELF64 = true
	}
}

func setEIData(b byte) {
	switch b {
	case 0:
		EI_DATA = "ELFDATANONE" //无效数据编码
		LittleEndian = true
	case 1:
		EI_DATA = "ELFDATA2LSB" //小端
		LittleEndian = true
	case 2:
		EI_DATA = "ELFDATA2MSB" //大端
		LittleEndian = false
	}
}

func printHeader(header ELFHeader64) {
	fmt.Printf("ELF Header:\n")
	fmt.Printf("  Magic:   ")
	for _, bt := range header.e_ident {
		fmt.Printf("%2x ", bt)
	}
	fmt.Printf("\n")
	switch header.e_ident[4] {
	case 0:
		fmt.Printf("  Class:                             NONE\n")
	case 1:
		fmt.Printf("  Class:                             ELF32\n")
	case 2:
		fmt.Printf("  Class:                             ELF64\n")
	}

	fmt.Printf("elfHeader.e_type=%d\n", header.e_type)
	fmt.Printf("elfHeader.e_machine=%d\n", header.e_machine)
	fmt.Printf("elfHeader.e_version=%d\n", header.e_version)
	fmt.Printf("elfHeader.e_entry=%d\n", header.e_entry)
	fmt.Printf("elfHeader.e_phoff=%d\n", header.e_phoff)
	fmt.Printf("elfHeader.e_shoff=%d\n", header.e_shoff)
	fmt.Printf("elfHeader.e_flags=%d\n", header.e_flags)
	fmt.Printf("elfHeader.e_ehsize=%d\n", header.e_ehsize)
	fmt.Printf("elfHeader.e_phentsize=%d\n", header.e_phentsize)
	fmt.Printf("elfHeader.e_phnum=%d\n", header.e_phnum)
	fmt.Printf("elfHeader.e_shentsize=%d\n", header.e_shentsize)
	fmt.Printf("elfHeader.e_shnum=%d\n", header.e_shnum)
	fmt.Printf("elfHeader.e_shstrndx=%d\n", header.e_shstrndx)
}

func printProgramHeader(fileName string, elfheader ELFHeader64) {

	fmt.Printf("   Type           Offset             VirtAddr           PhysAddr\n")
	fmt.Printf("                  FileSiz            MemSiz              Flags  Align\n")
	phdrs := getPhdrs(fileName, elfheader)

	for _, phdr := range phdrs {
		printPhdr(phdr)
	}

}

func getPhdrs(fileName string, elfheader ELFHeader64) []Phdr64 {
	var phdrs []Phdr64

	f, _ := os.Open(fileName)
	b := make([]byte, elfheader.e_phentsize)
	bufr := bufio.NewReader(f)
	_, err := f.Seek(int64(elfheader.e_phoff), 0)
	if err != nil {
		log.Fatal(err)
	} else {
		var i uint16
		for i = 0; i < elfheader.e_phnum; i++ {
			_, err = io.ReadFull(bufr, b)
			phdr := bytesToPhdr(b)
			phdrs = append(phdrs, phdr)
		}
		if err != nil {
			log.Fatal(err)
		}
	}

	return phdrs
}

func bytesToPhdr(b []byte) Phdr64 {
	var phdr Phdr64
	phdr.p_type = GetUINT32(b[0:4], LittleEndian)
	phdr.p_flags = GetUINT32(b[4:8], LittleEndian)
	phdr.p_offset = GetUINT64(b[8:16], LittleEndian)
	phdr.p_vaddr = GetUINT64(b[16:24], LittleEndian)
	phdr.p_paddr = GetUINT64(b[24:32], LittleEndian)
	phdr.p_filesz = GetUINT64(b[32:40], LittleEndian)
	phdr.p_memsz = GetUINT64(b[40:48], LittleEndian)
	phdr.p_align = GetUINT64(b[48:56], LittleEndian)
	return phdr
}

func printPhdr(phdr Phdr64) {
	// LOAD           0x0000000000000000 0x0000000000200000 0x0000000000200000
	//
	//	0x0000000000022950 0x0000000000022950  R E    0x1000
	fmt.Printf("   %d\t0x%x 0x%x 0x%x\n", phdr.p_type, phdr.p_offset, phdr.p_vaddr, phdr.p_paddr)
	fmt.Printf("   \t0x%x 0x%x %b 0x%x\n", phdr.p_filesz, phdr.p_memsz, phdr.p_flags, phdr.p_align)
}

func printSectionHeader(fileName string, elfheader ELFHeader64) {
	headers := getSectionsHeader(fileName, elfheader)
	fmt.Printf("[Nr] Name              Type             Address           Offset\n")
	fmt.Printf("     Size              EntSize          Flags  Link  Info  Align\n")
	for i, shdr := range headers {
		printShdr(uint16(i), shdr)
	}
}

func printShdr(index uint16, shdr Shdr64) {
	//   [ 0]                   NULL             0000000000000000  00000000
	//        0000000000000000  0000000000000000           0     0     0
	fmt.Printf("[%d]\t%s %d 0x%x 0x%x\n", index, shdr.sh_name_str, shdr.sh_type, shdr.sh_addr, shdr.sh_offset)
	fmt.Printf("\t0x%x 0x%x %b 0x%x 0x%x 0x%x\n", shdr.sh_size, shdr.sh_entsize, shdr.sh_flags, shdr.sh_link, shdr.sh_info, shdr.sh_addralign)
}

func getSectionsHeader(fileName string, elfheader ELFHeader64) []Shdr64 {
	var headers []Shdr64
	f, _ := os.Open(fileName)
	b := make([]byte, elfheader.e_shentsize)
	bufr := bufio.NewReader(f)
	_, err := f.Seek(int64(elfheader.e_shoff), 0)
	if err != nil {
		log.Fatal(err)
	} else {
		var i uint16
		for i = 0; i < elfheader.e_shnum; i++ {
			_, err = io.ReadFull(bufr, b)
			shdr := bytesToShdr(b)
			headers = append(headers, shdr)
			if shdr.sh_type == 3 && i == elfheader.e_shnum-1 {
				shstrtab = shdr
			}
		}
		if err != nil {
			log.Fatal(err)
		}
	}

	_, m := getSectionString(fileName, shstrtab)
	var secheaders []Shdr64
	if m != nil {
		for _, shdr := range headers {
			shdr.sh_name_str = m[int(shdr.sh_name)]
			secheaders = append(secheaders, shdr)
		}
	}

	return secheaders
}

func bytesToShdr(b []byte) Shdr64 {
	var shdr Shdr64

	shdr.sh_name = GetUINT32(b[0:4], LittleEndian)
	shdr.sh_type = GetUINT32(b[4:8], LittleEndian)
	shdr.sh_flags = GetUINT64(b[8:16], LittleEndian)
	shdr.sh_addr = GetUINT64(b[16:24], LittleEndian)
	shdr.sh_offset = GetUINT64(b[24:32], LittleEndian)
	shdr.sh_size = GetUINT64(b[32:40], LittleEndian)
	shdr.sh_link = GetUINT32(b[40:44], LittleEndian)
	shdr.sh_info = GetUINT32(b[44:48], LittleEndian)
	shdr.sh_addralign = GetUINT64(b[48:56], LittleEndian)
	shdr.sh_entsize = GetUINT64(b[56:64], LittleEndian)

	return shdr
}

func getSectionString(fileName string, shdr Shdr64) ([]string, map[int]string) {
	f, _ := os.Open(fileName)
	b := make([]byte, shdr.sh_size)
	bufr := bufio.NewReader(f)
	_, err := f.Seek(int64(shdr.sh_offset), 0)
	if err != nil {
		log.Fatal(err)
	} else {
		_, err = io.ReadFull(bufr, b)
		strs := GetStrings(b)
		return strs, GetStringLenMap(strs)
	}
	return nil, nil
}

func GetUINT64(buf []byte, asc bool) uint64 {
	if asc {
		return binary.LittleEndian.Uint64(buf)
	} else {
		return binary.BigEndian.Uint64(buf)
	}
}

func GetUINT32(buf []byte, asc bool) uint32 {
	if asc {
		return binary.LittleEndian.Uint32(buf)
	} else {
		return binary.BigEndian.Uint32(buf)
	}
}

func GetUINT16(buf []byte, asc bool) uint16 {
	if asc {
		return binary.LittleEndian.Uint16(buf)
	} else {
		return binary.BigEndian.Uint16(buf)
	}
}

func GetInt(buf []byte, asc bool, typestr string) int {
	var i int
	switch typestr {
	case "UINT16":
		i = int(GetUINT16(buf, asc))
	case "UINT32":
		i = int(GetUINT32(buf, asc))
	case "UINT64":
		i = int(GetUINT64(buf, asc))
	}
	return i
}

func GetStrings(buf []byte) []string {
	var strs []string
	var i int
	for i = 0; i < len(buf); i++ {
		j := i
		for buf[j] != 0 {
			j++
		}
		str := string(buf[i:j])
		strs = append(strs, str)
		i = j
	}

	return strs
}

func GetStringLenMap(strs []string) map[int]string {
	m := make(map[int]string)
	i := 0
	for _, str := range strs {
		m[i] = str
		i = i + len(str) + 1
	}
	return m
}

func UINT32aglinTo(i uint32, a uint32) uint32 {
	if (i/a)*a == i {
		return i
	} else {
		return ((i / a) + 1) * a
	}
}
