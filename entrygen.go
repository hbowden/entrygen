/**
 * Copyright (c) 2016, Harrison Bowden, Minneapolis, MN
 *
 * Permission to use, copy, modify, and/or distribute this software for any purpose
 * with or without fee is hereby granted, provided that the above copyright notice
 * and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 **/

package main

import (
	"io/ioutil"
	"log"
	"bytes"
	"os"
	"time"
	"regexp"
	"runtime"
	"strconv"
	"text/template"
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
	ReturnType			string
}

func extractReturnType(proto string) (string) {
	var buffer bytes.Buffer
	for i := 2; i < len(proto); i++ {
		if string(proto[i]) == " " {
			break;
		}

		buffer.WriteString(string(proto[i]))
	}
	
	return buffer.String()
}

func createEntry(syscall string) {
	// Get the syscall number.
	syscallNumber := extractSyscallNumber(syscall)

	// Extract the syscall function prototype.
	proto := extractFunctionPrototype(syscall)

	// Count how many arguments the syscall has.
	count := extractTotalArgs(proto)

	// Figure out what type the syscall returns.
	returnType := extractReturnType(proto);

	// Grab the name of the syscall.
	syscallName := extractSyscallName(proto)

    // Get the current year.
	now := time.Now()
	year := strconv.Itoa(now.Year())

	// Create a syscall entry struct with the extracted info.
	e := Entry{EntryNumber: syscallNumber, TotalArgs: count, Year: year, ReturnType: returnType, SyscallName: syscallName}

    // Create a syscall entry template.
	t := template.New("entry.txt")
	t, err := template.ParseFiles("entry.txt", "warning.txt", "copyright.txt")
	if err != nil {
		log.Fatal(err)
		return
	}

    // Create a syscall entry file.
	f, err := os.Create("entry_" + syscallName + ".c")
	if err != nil {
		log.Fatal("Can't create file: ", err)
		return
	}

    // Close the file when it goes out of scope.
	defer f.Close()

    // Write the template to disk.
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
	var buffer bytes.Buffer
	var start = 0;
	for i := 2; i < len(syscall); i++ {
		if string(syscall[i]) == "(" {
			break
		} else if start == 1 {
           buffer.WriteString(string(syscall[i]))
		} else if string(syscall[i]) == " " {
			start = 1
			continue
		}
	}
	
	return buffer.String()
}

func extractTotalArgs(proto string) string {
	reg := regexp.MustCompilePOSIX("\\((.*?)\\)")
	params := reg.Find([]byte(proto))

	// Count represents how many parenthesis have been found. Default to one.
	var count int = 1;

    // Check if there are no arguments, if yes return zero.
	if string(params) == "(void)" {
		return string(0);
	}

    // Count the parenthesis and use that as the amount of args.
	for i := 0; i < len(params); i++ {
        if string(params[i]) == "(" {
        	continue
        } else if string(params[i]) == ")" {
        	break
        } else if string(params[i]) == "," {
        	count++;
        }
    }
	
	return strconv.Itoa(count)
}

func extractArgTypes(proto string) []string {
	var buffer bytes.Buffer
	reg := regexp.MustCompilePOSIX("\\((.*?)\\)")
	params := reg.Find([]byte(proto))

	// Parse out the parenthesis.
	for i := 0; i < len(params); i++ {
        if string(params[i]) == "(" {
        	continue
        } else if string(params[i]) == ")" {
        	break
        } else {
        	buffer.WriteString(string(params[i]))
        }
    }

    log.Println(buffer.String())
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
