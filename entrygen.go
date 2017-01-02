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
	"strings"
	"text/template"
	"time"
)

type Syscalls struct {
	Syscall       []SyscallName
	Year          string
	TotalSyscalls int
}

type SyscallName struct {
	Name    string
	Counter int
}

type Arg struct {
	ArgType   string
	GetArg    string
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
	TypeArray   []Arg
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

func getPointerArgType(str string) string {
	var buffer bytes.Buffer

	for i := 0; i < len(str); i++ {
		if string(str[i]) == "*" {
			buffer.WriteString(string(str[i]))
			break
		}

		buffer.WriteString(string(str[i]))
	}
	return buffer.String()
}

func removeArgName(str string) string {
	var buffer bytes.Buffer

	/* Check for a pointer. */
	if strings.Contains(str, "*") == true {
		return strings.TrimSpace(getPointerArgType(str))
	}

	for i := 0; i < len(str); i++ {
		if string(str[i]) == " " {
			/* If we are on the first or second iteration continue because
			some arg types contain leading spaces.  */
			if i == 0 || i == 1 {
				continue
			}
			/* Break out of the loop if it's not the first Loop
			   iteration, because we hit our first space.  */
			break
		}

		buffer.WriteString(string(str[i]))
	}
	return strings.TrimSpace(buffer.String())
}

func generateGetArgFunction(str []string) []string {
	funcArray := make([]string, len(str))
	for i := 0; i < len(str); i++ {
		switch removeArgName(str[i]) {
		case "int":
			funcArray[i] = "&generate_int"
		case "user_addr_t":
			funcArray[i] = "&generate_ptr"
		case "user_size_t":
			funcArray[i] = "&generate_int"
		case "uid_t":
			funcArray[i] = "&generate_int"
		case "pid_t":
			funcArray[i] = "&generate_pid"
		case "caddr_t":
			funcArray[i] = "&generate_ptr"
		case "size_t":
			funcArray[i] = "&generate_int"
			// Hack, need to fix removeArgName() so it trims the name properly.
		case "socklen_t	*anamelen":
			funcArray[i] = "&generate_ptr"
		case "socklen_t":
			funcArray[i] = "&generate_int"
		case "u_int":
			funcArray[i] = "&generate_int"
		case "u_long":
			funcArray[i] = "&generate_int"
		case "gid_t":
			funcArray[i] = "&generate_int"
		case "long":
			funcArray[i] = "&generate_int"
		case "u_int32_t":
			funcArray[i] = "&generate_int"
		case "id_t":
			funcArray[i] = "&generate_int"
		case "sigset_t":
			funcArray[i] = "&generate_int"
		case "uint64_t":
			funcArray[i] = "&generate_int"
		case "off_t":
			funcArray[i] = "&generate_int"
		case "fhandle_t":
			funcArray[i] = "&generate_ptr"
		case "uint32_t":
			funcArray[i] = "&generate_int"
		case "idtype_t":
			funcArray[i] = "&generate_int"
		case "siginfo_t":
			funcArray[i] = "&generate_int"
		case "void **":
			funcArray[i] = "&generate_ptr"
		case "size_t *":
			funcArray[i] = "&generate_ptr"
		case "semun_t":
			funcArray[i] = "&generate_int"
		case "key_t":
			funcArray[i] = "&generate_int"
		case "int	nsems":
			funcArray[i] = "&generate_int"
		case "sem_t":
			funcArray[i] = "&generate_int"
		case "int64_t":
			funcArray[i] = "&generate_int"
		case "int32_t":
			funcArray[i] = "&generate_int"
		case "uuid_t":
			funcArray[i] = "&generate_int"
		case "au_id_t":
			funcArray[i] = "&generate_int"
		case "uint8_t":
			funcArray[i] = "&generate_int"
		case "unsigned":
			funcArray[i] = "&generate_int"
		case "au_asid_t":
			funcArray[i] = "&generate_int"
		case "sae_associd_t":
			funcArray[i] = "&generate_int"
		case "sae_connid_t":
			funcArray[i] = "&generate_int"
		case "user_ssize_t":
			funcArray[i] = "&generate_int"
		case "struct msghdr *":
			funcArray[i] = "&generate_ptr"
		case "void *":
			funcArray[i] = "&generate_ptr"
		case "struct sockaddr *":
			funcArray[i] = "&generate_ptr"
		case "int *":
			funcArray[i] = "&generate_ptr"
		case "socklen_t	*":
			funcArray[i] = "&generate_ptr"
		case "char *":
			funcArray[i] = "&generate_ptr"
		case "struct __sigaction *":
			funcArray[i] = "&generate_ptr"
		case "struct sigaction *":
			funcArray[i] = "&generate_ptr"
		case "struct sigvec *":
			funcArray[i] = "&generate_ptr"
		case "struct sigaltstack *":
			funcArray[i] = "&generate_ptr"
		case "gid_t *":
			funcArray[i] = "&generate_ptr"
		case "struct itimerval *":
			funcArray[i] = "&generate_ptr"
		case "u_int32_t *":
			funcArray[i] = "&generate_ptr"
		case "struct timeval *":
			funcArray[i] = "&generate_ptr"
		case "struct timezone *":
			funcArray[i] = "&generate_ptr"
		case "uint64_t *":
			funcArray[i] = "&generate_ptr"
		case "struct rusage *":
			funcArray[i] = "&generate_ptr"
		case "struct iovec *":
			funcArray[i] = "&generate_ptr"
		case "unsigned char *":
			funcArray[i] = "&generate_ptr"
		case "const struct timespec *":
			funcArray[i] = "&generate_ptr"
		case "struct statfs *":
			funcArray[i] = "&generate_ptr"
		case "fhandle_t *":
			funcArray[i] = "&generate_ptr"
		case "const char *":
			funcArray[i] = "&generate_ptr"
		case "siginfo_t *":
			funcArray[i] = "&generate_ptr"
		case "void*":
			funcArray[i] = "&generate_ptr"
		case "size_t*":
			funcArray[i] = "&generate_ptr"
		case "struct ucontext *":
			funcArray[i] = "&generate_ptr"
		case "struct rlimit *":
			funcArray[i] = "&generate_ptr"
		case "long *":
			funcArray[i] = "&generate_ptr"
		case "struct attrlist *":
			funcArray[i] = "&generate_ptr"
		case "u_long *":
			funcArray[i] = "&generate_ptr"
		case "struct fssearchblock *":
			funcArray[i] = "&generate_ptr"
		case "uint32_t *":
			funcArray[i] = "&generate_ptr"
		case "struct searchstate *":
			funcArray[i] = "&generate_ptr"
		case "struct pollfd *":
			funcArray[i] = "&generate_ptr"
		case "struct eventreq *":
			funcArray[i] = "&generate_ptr"
		case "pid_t *":
			funcArray[i] = "&generate_ptr"
		case "const struct _posix_spawn_args_desc *":
			funcArray[i] = "&generate_ptr"
		case "struct sembuf *":
			funcArray[i] = "&generate_ptr"
		case "struct	msqid_ds *":
			funcArray[i] = "&generate_ptr"
		case "struct shmid_ds *":
			funcArray[i] = "&generate_ptr"
		case "sem_t *":
			funcArray[i] = "&generate_ptr"
		case "off_t *":
			funcArray[i] = "&generate_ptr"
		case "struct sf_hdtr *":
			funcArray[i] = "&generate_ptr"
		case "struct statfs64 *":
			funcArray[i] = "&generate_ptr"
		case "au_id_t *":
			funcArray[i] = "&generate_ptr"
		case "struct auditinfo_addr *":
			funcArray[i] = "&generate_ptr"
		case "const struct kevent *":
			funcArray[i] = "&generate_ptr"
		case "struct kevent *":
			funcArray[i] = "&generate_ptr"
		case "const struct kevent64_s *":
			funcArray[i] = "&generate_ptr"
		case "struct kevent64_s *":
			funcArray[i] = "&generate_ptr"
		case "const struct kevent_qos_s *":
			funcArray[i] = "&generate_ptr"
		case "struct mac *":
			funcArray[i] = "&generate_ptr"
		case "guardid_t *":
			funcArray[i] = "&generate_ptr"
		case "const struct shared_file_mapping_np *":
			funcArray[i] = "&generate_ptr"
		case "sa_endpoints_t *":
			funcArray[i] = "&generate_ptr"
		case "const struct iovec *":
			funcArray[i] = "&generate_ptr"
		case "sae_connid_t *":
			funcArray[i] = "&generate_ptr"
		case "uint8_t *":
			funcArray[i] = "&generate_ptr"
		case "struct necp_aggregate_result *":
			funcArray[i] = "&generate_ptr"
		case "user_addr_t *":
			funcArray[i] = "&generate_ptr"
		case "socklen_t *":
			funcArray[i] = "&generate_ptr"
		case "const struct fhandle *":
			funcArray[i] = "&generate_ptr"
		case "uid_t *":
			funcArray[i] = "&generate_ptr"
		case "struct kevent_qos_s *":
			funcArray[i] = "&generate_ptr"
		case "const struct sigset_t *":
			funcArray[i] = "&generate_ptr"
		case "uint64_t*":
			funcArray[i] = "&generate_ptr"
		case "const sa_endpoints_t *":
			funcArray[i] = "&generate_ptr"
		case "struct msghdr_x *":
			funcArray[i] = "&generate_ptr"
		case "const guardid_t *":
			funcArray[i] = "&generate_ptr"
		case "struct kpersona_info *":
			funcArray[i] = "&generate_ptr"
		case "mach_port_name_t":
			funcArray[i] = "&generate_mach_port"
		default:
			log.Printf("NOT IMPLEMENTED: %s\n", removeArgName(str[i]))
		}
	}
	return funcArray
}

func generateGetType(str []string) []string {
	funcArray := make([]string, len(str))
	for i := 0; i < len(str); i++ {
		switch removeArgName(str[i]) {
		case "au_asid_t":
			funcArray[i] = "INT"
		case "uint32_t":
			funcArray[i] = "INT"
		case "int":
			funcArray[i] = "INT"
		case "user_addr_t":
			funcArray[i] = "ADDRESS"
		case "user_size_t":
			funcArray[i] = "INT"
		case "uid_t":
			funcArray[i] = "INT"
		case "pid_t":
			funcArray[i] = "PID"
		case "caddr_t":
			funcArray[i] = "ADDRESS"
		case "size_t":
			funcArray[i] = "INT"
			// Hack, need to fix removeArgName() so it trims the name properly.
		case "socklen_t	*anamelen":
			funcArray[i] = "ADDRESS"
		case "socklen_t":
			funcArray[i] = "INT"
		case "u_int":
			funcArray[i] = "INT"
		case "u_long":
			funcArray[i] = "INT"
		case "gid_t":
			funcArray[i] = "INT"
		case "long":
			funcArray[i] = "INT"
		case "u_int32_t":
			funcArray[i] = "INT"
		case "id_t":
			funcArray[i] = "INT"
		case "sigset_t":
			funcArray[i] = "INT"
		case "uint64_t":
			funcArray[i] = "INT"
		case "off_t":
			funcArray[i] = "INT"
		case "idtype_t":
			funcArray[i] = "INT"
		case "siginfo_t":
			funcArray[i] = "INT"
		case "void**":
			funcArray[i] = "ADDRESS"
		case "size_t*":
			funcArray[i] = "ADDRESS"
		case "semun_t":
			funcArray[i] = "INT"
		case "key_t":
			funcArray[i] = "INT"
		case "int	nsems":
			funcArray[i] = "INT"
		case "sem_t":
			funcArray[i] = "INT"
		case "int64_t":
			funcArray[i] = "INT"
		case "int32_t":
			funcArray[i] = "INT"
		case "unsigned":
			funcArray[i] = "INT"
		case "sae_associd_t":
			funcArray[i] = "INT"
		case "sae_connid_t":
			funcArray[i] = "INT"
		case "uuid_t":
			funcArray[i] = "INT"
		case "user_ssize_t":
			funcArray[i] = "INT"
		case "struct msghdr *":
			funcArray[i] = "ADDRESS"
		case "void *":
			funcArray[i] = "ADDRESS"
		case "struct sockaddr *":
			funcArray[i] = "ADDRESS"
		case "int *":
			funcArray[i] = "ADDRESS"
		case "socklen_t	*":
			funcArray[i] = "ADDRESS"
		case "char *":
			funcArray[i] = "ADDRESS"
		case "struct __sigaction *":
			funcArray[i] = "ADDRESS"
		case "struct sigaction *":
			funcArray[i] = "ADDRESS"
		case "struct sigvec *":
			funcArray[i] = "ADDRESS"
		case "struct sigaltstack *":
			funcArray[i] = "ADDRESS"
		case "gid_t *":
			funcArray[i] = "ADDRESS"
		case "struct itimerval *":
			funcArray[i] = "ADDRESS"
		case "u_int32_t *":
			funcArray[i] = "ADDRESS"
		case "struct timeval *":
			funcArray[i] = "ADDRESS"
		case "struct timezone *":
			funcArray[i] = "ADDRESS"
		case "uint64_t *":
			funcArray[i] = "ADDRESS"
		case "struct rusage *":
			funcArray[i] = "ADDRESS"
		case "struct iovec *":
			funcArray[i] = "ADDRESS"
		case "unsigned char *":
			funcArray[i] = "ADDRESS"
		case "const struct timespec *":
			funcArray[i] = "ADDRESS"
		case "struct statfs *":
			funcArray[i] = "ADDRESS"
		case "fhandle_t *":
			funcArray[i] = "ADDRESS"
		case "const char *":
			funcArray[i] = "ADDRESS"
		case "siginfo_t *":
			funcArray[i] = "ADDRESS"
		case "void*":
			funcArray[i] = "ADDRESS"
		case "struct ucontext *":
			funcArray[i] = "ADDRESS"
		case "struct rlimit *":
			funcArray[i] = "ADDRESS"
		case "long *":
			funcArray[i] = "ADDRESS"
		case "struct attrlist *":
			funcArray[i] = "ADDRESS"
		case "u_long *":
			funcArray[i] = "ADDRESS"
		case "struct fssearchblock *":
			funcArray[i] = "ADDRESS"
		case "uint32_t *":
			funcArray[i] = "ADDRESS"
		case "struct searchstate *":
			funcArray[i] = "ADDRESS"
		case "struct pollfd *":
			funcArray[i] = "ADDRESS"
		case "struct eventreq *":
			funcArray[i] = "ADDRESS"
		case "pid_t *":
			funcArray[i] = "ADDRESS"
		case "const struct _posix_spawn_args_desc *":
			funcArray[i] = "ADDRESS"
		case "struct sembuf *":
			funcArray[i] = "ADDRESS"
		case "struct	msqid_ds *":
			funcArray[i] = "ADDRESS"
		case "struct shmid_ds *":
			funcArray[i] = "ADDRESS"
		case "sem_t *":
			funcArray[i] = "ADDRESS"
		case "off_t *":
			funcArray[i] = "ADDRESS"
		case "struct sf_hdtr *":
			funcArray[i] = "ADDRESS"
		case "struct statfs64 *":
			funcArray[i] = "ADDRESS"
		case "au_id_t *":
			funcArray[i] = "ADDRESS"
		case "struct auditinfo_addr *":
			funcArray[i] = "ADDRESS"
		case "const struct kevent *":
			funcArray[i] = "ADDRESS"
		case "struct kevent *":
			funcArray[i] = "ADDRESS"
		case "const struct kevent64_s *":
			funcArray[i] = "ADDRESS"
		case "struct kevent64_s *":
			funcArray[i] = "ADDRESS"
		case "const struct kevent_qos_s *":
			funcArray[i] = "ADDRESS"
		case "struct mac *":
			funcArray[i] = "ADDRESS"
		case "guardid_t *":
			funcArray[i] = "ADDRESS"
		case "const struct shared_file_mapping_np *":
			funcArray[i] = "ADDRESS"
		case "sa_endpoints_t *":
			funcArray[i] = "ADDRESS"
		case "const struct iovec *":
			funcArray[i] = "ADDRESS"
		case "sae_connid_t *":
			funcArray[i] = "ADDRESS"
		case "uint8_t *":
			funcArray[i] = "ADDRESS"
		case "struct necp_aggregate_result *":
			funcArray[i] = "ADDRESS"
		case "user_addr_t *":
			funcArray[i] = "ADDRESS"
		case "socklen_t *":
			funcArray[i] = "ADDRESS"
		case "const struct fhandle *":
			funcArray[i] = "ADDRESS"
		case "uid_t *":
			funcArray[i] = "ADDRESS"
		case "struct kevent_qos_s *":
			funcArray[i] = "ADDRESS"
		case "const struct sigset_t *":
			funcArray[i] = "ADDRESS"
		case "uint64_t*":
			funcArray[i] = "ADDRESS"
		case "const sa_endpoints_t *":
			funcArray[i] = "ADDRESS"
		case "struct msghdr_x *":
			funcArray[i] = "ADDRESS"
		case "const guardid_t *":
			funcArray[i] = "ADDRESS"
		case "struct kpersona_info *":
			funcArray[i] = "ADDRESS"
		case "size_t *":
			funcArray[i] = "ADDRESS"
		case "mach_port_name_t":
			funcArray[i] = "ADDRESS"
		default:
			log.Printf("Missing type: %s", removeArgName(str[i]))
		}
	}
	return funcArray
}

func generateGetArgArray(proto string, count string) []string {
	// var variables int
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
	var str = make([]string, totalArgs+1)
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

	// Take the translated types and generate the right get arg function name.
	return generateGetArgFunction(str)
}

func generateGetTypeArray(proto string, count string) []string {
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
	var str = make([]string, totalArgs+1)
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

	return generateGetType(str)
}

func createArgArray(types []string, args []string, count string) []Arg {
	// Convert string to a number.
	totalArgs, err := strconv.Atoi(count)
	if err != nil {
		totalArgs = 0
	}

	argArray := make([]Arg, totalArgs)

	symbolArray := [...]string{"FIRST_ARG",
		"SECOND_ARG",
		"THIRD_ARG",
		"FOURTH_ARG",
		"FIFTH_ARG",
		"SIXTH_ARG",
		"SEVENTH_ARG",
		"EIGTH_ARG",
		"NINTH_ARG",
		"TENTH_ARG",
		"ELEVENTH_ARG",
		"TWELFTH_ARG"}

	for i := 0; i < totalArgs; i++ {
		argArray[i].GetArg = args[i]
		argArray[i].ArgSymbol = symbolArray[i]
		argArray[i].ArgType = types[i]
	}

	return argArray
}

func checkEntry(entry Entry) bool {

	for i := 0; i < len(entry.ArgArray); i++ {
		if len(entry.ArgArray[i].GetArg) == 0 {
			log.Println(entry.SyscallName)
		}
	}

	return true
}

func writeEntry(entry Entry, name string, dir string) {
	if len(name) == 0 {
		return
	}

	if checkEntry(entry) != true {
		return
	}

	// Create a syscall entry template.
	t := template.New("input/entry.txt")
	t, err := template.ParseFiles("input/entry.txt", "input/warning.txt", "input/copyright.txt")
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

func createEntryObject(syscall string) Entry {
	// Extract the syscall function prototype.
	proto := extractFunctionPrototype(syscall)

	// Grab the name of the syscall.
	syscallName := extractSyscallName(proto)

	var e Entry

	// Skip empty syscall entries.
	if syscallName == "enosys" || syscallName == "nosys" {
		return e
	}

	// Count how many arguments the syscall has.
	count := extractTotalArgs(proto)

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

	e = Entry{EntryNumber: syscallNumber,
		TotalArgs:   count,
		Year:        year,
		ReturnType:  returnType,
		SyscallName: syscallName,
		ArgArray:    argArray}

	return e
}

func createEntry(syscall string, basedir string) {
	// Extract information from string and create a
	// syscall entry object with the information.
	entry := createEntryObject(syscall)

	// Write the syscall entry to disk.
	writeEntry(entry, entry.SyscallName, basedir)
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

	if strings.Contains(proto, ",") != true {
		return "0"
	}

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

func getSyscallName(syscall string) string {

	// Extract the syscall function prototype.
	proto := extractFunctionPrototype(syscall)

	// Grab the name of the syscall.
	syscallName := extractSyscallName(proto)

	return syscallName
}

func createSyscallList(syscalls []string, dir string) {
	t := template.New("input/syscall_list.txt")
	t, err := template.ParseFiles("input/syscall_list.txt", "input/warning.txt", "input/copyright.txt")
	if err != nil {
		log.Fatal(err)
		return
	}

	f, err := os.Create(dir + "/syscall_list.h")
	if err != nil {
		log.Fatal("Can't create file: ", err)
		return
	}

	// Close the file when it goes out of scope.
	defer f.Close()

	now := time.Now()
	year := strconv.Itoa(now.Year())

	var names []SyscallName

	for i := 0; i < len(syscalls); i++ {
		// Skip empty syscall entries.
		if syscalls[i] == "enosys" || syscalls[i] == "nosys" {
			continue
		}
		name := SyscallName{Name: "entry_" + syscalls[i]}
		names = append(names, name)
	}

	s := Syscalls{Syscall: names, Year: year}

	// Write the template to disk.
	err = t.Execute(f, s)
	if err != nil {
		log.Fatal("Can't write entry file: ", err)
		return
	}
}

func createSyscallTables(syscalls []string, dir string) {
	t := template.New("input/syscall_table.txt")
	t, err := template.ParseFiles("input/syscall_table.txt", "input/warning.txt", "input/copyright.txt")
	if err != nil {
		log.Fatal(err)
		return
	}

	f, err := os.Create(dir + "/" + dir + "_table.h")
	if err != nil {
		log.Fatal("Can't create file: ", err)
		return
	}

	// Close the file when it goes out of scope.
	defer f.Close()

	now := time.Now()
	year := strconv.Itoa(now.Year())

	var names []SyscallName
	counter := 0
	var i int

	for i = 0; i < len(syscalls); i++ {
		// Skip empty syscall entries.
		if syscalls[i] == "enosys" || syscalls[i] == "nosys" {
			counter--
			continue
		}
		name := SyscallName{Name: "entry_" + syscalls[i], Counter: i + counter}
		names = append(names, name)
	}

	s := Syscalls{Syscall: names, Year: year, TotalSyscalls: i + counter}

	// Write the template to disk.
	err = t.Execute(f, s)
	if err != nil {
		log.Fatal("Can't write entry file: ", err)
		return
	}
}

func generateOutput(platform string, config []byte) {
	// Extract all the syscall function prototypes and syscall numbers.
	reg := regexp.MustCompilePOSIX("(^[0-9]+).*?")
	syscalls := reg.FindAll(config, len(config))

	// Check if a platform folder has been created, if not
	// create one using the name of the os.
	if _, err := os.Stat(platform); os.IsNotExist(err) {
		os.Mkdir(platform, 0777)
	}

	var names []string

	// Loop and create syscall entries for this platform.
	for i := 0; i < len(syscalls); i++ {
		s := string(syscalls[i])
		createEntry(s, platform)
		namesArray := names
		names = make([]string, i+1)
		copy(names, namesArray)
		name := getSyscallName(s)
		names[i] = name
	}

	createSyscallList(names, platform)
	createSyscallTables(names, platform)

	return
}

func defaultBuild() {
	var err error
	var SyscallListBuf []byte

	// Check our OS and read it's syscall.master file.
	if runtime.GOOS == "freebsd" {
		SyscallListBuf, err = ioutil.ReadFile("input/freebsd-syscall.master")
		if err != nil {
			log.Fatal(err)
			return
		}
	}

	if runtime.GOOS == "darwin" {
		SyscallListBuf, err = ioutil.ReadFile("input/osx-syscall.master")
		if err != nil {
			log.Fatal(err)
			return
		}
	}

	generateOutput(runtime.GOOS, SyscallListBuf)

	return
}

func getConfig(os string) []byte {
	var err error
	var SyscallListBuf []byte

	if os == "freebsd" {
		SyscallListBuf, err = ioutil.ReadFile("input/freebsd-syscall.master")
		if err != nil {
			log.Fatal(err)
			return nil
		}
	}

	if os == "darwin" {
		SyscallListBuf, err = ioutil.ReadFile("input/osx-syscall.master")
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
	generateOutput(*os, config)

	return
}
