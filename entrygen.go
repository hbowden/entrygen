package main

import (
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"html/template"
)

type Entry struct {
	Year            string // The year the output files were generated. Used for copyright.
	SyscallName     string // The name of the system call, ie read, write, wait4, etc.
	SyscallSymbol   string // The symbolic name of the syscall, ie the first argument to syscall().
	Status          string // Whether the syscall is on or off, defaults to on.
	NeedAlarm       string // If the syscall is blocking set to yes.
	RequiresRoot    string
	ArgTypeArray    []string
	TotalArgs       string
	EntryNumber     string
	ArgContextArray []string
	GetArgArray     []string
	TestSyscall     string
	TestID          string
}

func createEntry(syscall string) {
	// Get the syscall number.
	syscallNumber := extractSyscallNumber(syscall)
	proto := extractFunctionPrototype(syscall)
	_ = extractSyscallName(proto)

	// Create a syscall entry struct with the extracted info.
	e := Entry{EntryNumber: syscallNumber}

	t := template.New("entry.txt")

	t, err := template.ParseFiles("entry.txt")
	if err != nil {
		log.Fatal(err)
		return
	}

	f, err := os.Create("entry_test.c")
	if err != nil {
		log.Fatal("Can't create file: ", err)
		return
	}

	defer f.Close()

	err = t.Execute(f, e)
	if err != nil {
		log.Fatal("Can't write entry file: ", err)
		return
	}
}

func extractFunctionPrototype(syscall string) string {
	reg := regexp.MustCompilePOSIX("\\{(.*?)\\}")
	proto := reg.Find([]byte(syscall))
	return string(proto)
}

func extractSyscallName(syscall string) string {
	reg := regexp.MustCompilePOSIX("^[0-9]+")
	syscallNumber := reg.Find([]byte(syscall))
	return string(syscallNumber)
}

func extractTotalArgs(syscall string) string {
	return ""
}

func extractArgTypes(syscall string) []string {
	var str []string
	return str
}

func extractSyscallNumber(syscall string) string {
	reg := regexp.MustCompilePOSIX("^[0-9]+")
	syscallNumber := reg.Find([]byte(syscall))
	return string(syscallNumber)
}

func main() {
	var err error
	var SyscallListBuf []byte

	// Check our OS and read it's syscall.master file.
	if runtime.GOOS == "freebsd" {
		SyscallListBuf, err = ioutil.ReadFile("freebsd-syscall.master")
		if err != nil {
			log.Fatal(err)
			return
		}
	}

	if runtime.GOOS == "darwin" {
		SyscallListBuf, err = ioutil.ReadFile("osx-syscall.master")
		if err != nil {
			log.Fatal(err)
			return
		}
	}

	// Extract all the syscall function prototypes and syscall numbers.
	reg := regexp.MustCompilePOSIX("(^[0-9]+).*?")
	syscalls := reg.FindAll(SyscallListBuf, len(SyscallListBuf))

	// Loop and create syscall entries for this platform.
	for _, syscall := range syscalls {
		s := string(syscall)
		createEntry(s)
	}
	return
}
