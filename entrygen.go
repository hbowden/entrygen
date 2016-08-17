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
	"bytes"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"text/template"
	"time"
)

type Arg struct {
	ArgType string
	GetArg  string
	ArgSymbol string
}

type Entry struct {
	Year        string // The year the output files were generated. Used for copyright.
	SyscallName string // The name of the system call, ie read, write, wait4, etc.
	Status      string // Whether the syscall is on or off, defaults to on.
	TotalArgs   string
	EntryNumber string
	ReturnType  string
	ArgArray    []Arg
}

func extractReturnType(proto string) string {
	var buffer bytes.Buffer
	for i := 2; i < len(proto); i++ {
		if string(proto[i]) == " " {
			break
		}

		buffer.WriteString(string(proto[i]))
	}

	return buffer.String()
}

func translateTypes(str []string) []string {
	typeArray := make([]string, len(str))
	for i := 0; i < len(str); i++ {
		switch str[i] {
		case "user_addr_t":
			typeArray[i] = "void *"
		}
	}

	return typeArray
}

func generateGetArgFunction(str []string) []string {

	return str
}

func generateGetArgArray(proto string, count string) []string {
	reg := regexp.MustCompilePOSIX("\\((.*?)\\)")
	params := reg.Find([]byte(proto))

	// Check if there are no arguments, if yes return zero.
	if string(params) == "(void)" {
		return nil
	}

	// Convert string to a number.
	totalArgs, err := strconv.Atoi(count)
	if err != nil {
		log.Fatal("Can't convert string")
		return nil
	}

	// Declare some variables and make a string slice.
	var str = make([]string, totalArgs)
	var buffer bytes.Buffer
	commaCount := 0

	// Parse out arguments types and stick them into the string slice, str.
	for i := 1; i < len(params); i++ {
		if string(params[i]) == ")" {
			str[commaCount] = buffer.String()
			break
		} else if string(params[i]) == "," {
			str[commaCount] = buffer.String()
			buffer.Reset()
			commaCount++
		} else {
			buffer.WriteString(string(params[i]))
		}
	}

	/* The arguments grabbed from syscall.master use the kernel
	space type names for argument types. Translate the kernel names to their
	equivalent userspace types. */
	str = translateTypes(str)

	// Take the translated types and generate the right get arg function name.
	return generateGetArgFunction(str)
}

func generateGetTypeArray(proto string, count string) []string {
	var str []string
	return str
}

func createArgArray(types []string, args []string, count string) []Arg {
	// Convert string to a number.
	totalArgs, err := strconv.Atoi(count)
	if err != nil {
	    totalArgs = 0;
	}

	argArray := make([]Arg, totalArgs)

	symbolArray := [...]string{"FIRST_ARG", "SECOND_ARG", "THIRD_ARG", "FOURTH_ARG", "FIFTH_ARG", "SIXTH_ARG", "SEVENTH_ARG", "EIGTH_ARG"}

	for i := 0; i < totalArgs; i++ {
		argArray[i].GetArg = args[i]
		//argArray[i].ArgType = types[i]
		argArray[i].ArgSymbol = symbolArray[i]
	}

	return argArray
}

func writeEntry(entry Entry, name string, dir string) {
	// Create a syscall entry template.
	t := template.New("entry.txt")
	t, err := template.ParseFiles("entry.txt", "warning.txt", "copyright.txt")
	if err != nil {
		log.Fatal(err)
		return
	}

	// Create a syscall entry file with the system call name appened to entry_.
	f, err := os.Create(dir + "/entry_" + name + ".c")
	if err != nil {
		log.Fatal("Can't create file: ", err)
		return
	}

	// Close the file when it goes out of scope.
	defer f.Close()

	// Write the template to disk.
	err = t.Execute(f, entry)
	if err != nil {
		log.Fatal("Can't write entry file: ", err)
		return
	}
}

func createEntry(syscall string, basedir string) {

	// Extract the syscall function prototype.
	proto := extractFunctionPrototype(syscall)

	// Grab the name of the syscall.
	syscallName := extractSyscallName(proto)

  // Skip empty syscall entries.
	if syscallName == "enosys" || syscallName == "nosys" {
  	return;
	}

	// Count how many arguments the syscall has.
	count := extractTotalArgs(proto)

  // Let the user know what were creating.
	log.Printf("%s: entry_%s.c", basedir, syscallName)

	// Get the syscall number.
	syscallNumber := extractSyscallNumber(syscall)

	// Figure out what type the syscall returns.
	returnType := extractReturnType(proto)

	// Generate the get argument array.
	args := generateGetArgArray(proto, count)

	// Generate get type array.
	types := generateGetTypeArray(proto, count)

	// Get the current year.
	now := time.Now()
	year := strconv.Itoa(now.Year())

	argArray := createArgArray(types, args, count)

	// for i := 0; i < len(argArray); i++ {
	// 	log.Printf("Get: %s", argArray[i].GetArg)
	// 	log.Printf("Type: %s", argArray[i].ArgType)
	// 	log.Printf("Sym: %s", argArray[i].ArgSymbol)
	// }

	// Create a syscall entry struct with the extracted info.
	e := Entry{EntryNumber: syscallNumber,
		TotalArgs:   count,
		Year:        year,
		ReturnType:  returnType,
		SyscallName: syscallName,
		ArgArray:    argArray}

		writeEntry(e, syscallName, basedir)
}

func extractFunctionPrototype(syscall string) string {
	reg := regexp.MustCompilePOSIX("\\{(.*?)\\}")
	proto := reg.Find([]byte(syscall))
	return string(proto)
}

func extractSyscallName(syscall string) string {
	var buffer bytes.Buffer
	var start = 0
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
	var count int = 1

	// Check if there are no arguments, if yes return zero.
	if string(params) == "(void)" {
		return string(0)
	}

	// Count the parenthesis and use that as the amount of args.
	for i := 0; i < len(params); i++ {
		if string(params[i]) == "(" {
			continue
		} else if string(params[i]) == ")" {
			break
		} else if string(params[i]) == "," {
			count++
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

func generateEntries(platform string, config []byte) {

	// Extract all the syscall function prototypes and syscall numbers.
	reg := regexp.MustCompilePOSIX("(^[0-9]+).*?")
	syscalls := reg.FindAll(config, len(config))

	// Check if a platform folder has been created, if not
	// create one using the name of the os.
	if _, err := os.Stat(platform); os.IsNotExist(err) {
		os.Mkdir(platform, 0777)
	}

	// Loop and create syscall entries for this platform.
	for _, syscall := range syscalls {
		s := string(syscall)
		createEntry(s, platform)
	}

	return
}

func defaultBuild() {
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

	generateEntries(runtime.GOOS, SyscallListBuf)

	return
}

func getConfig(os string) []byte {
	var err error
	var SyscallListBuf []byte

	if os == "freebsd" {
		SyscallListBuf, err = ioutil.ReadFile("freebsd-syscall.master")
		if err != nil {
			log.Fatal(err)
			return nil
		}
	}

	if os == "darwin" {
		SyscallListBuf, err = ioutil.ReadFile("osx-syscall.master")
		if err != nil {
			log.Fatal(err)
			return nil
		}
	}

	return SyscallListBuf
}

func main() {
	var os = flag.String("os", "default", "The operating system to generate syscall entry for.")
	flag.Parse()

	// Check if no build options, were selected. If not just generate
	// syscall entries for the operating system we are running on.
	if *os == "default" {
		log.Printf("No operating system selected, defaulting to: %s", runtime.GOOS)
		defaultBuild()
		return
	}

	// Load the config file into memory. We need the config file to know how
	// to generate syscall entries. The config file contains number of args
	// and syscall types, and more.
	config := getConfig(*os)

	// The user want's to generate syscall entries for a specific platform.
	generateEntries(*os, config)

	return
}
