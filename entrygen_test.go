package main

import (
	"testing"
)

func TestGetPointerArgType(t *testing.T) {
	testString := "char *pointer"
	str := getPointerArgType(testString)

	if str != "char *" {
		t.Errorf("Did not strip off name")
	}

}

func TestRemoveArgName(t *testing.T) {
	testString := "int fileport_makeport"
	str := removeArgName(testString)

	if str != "int" {
		t.Errorf("Did not strip off ' fileport_makeport': %s", str)
	}

	pointerString := "uid_t *uid"
	str = removeArgName(pointerString)
	if str != "uid_t *" {
		t.Errorf("Did not strip off uid")
	}

	structString := "struct shmid_ds *pointer"
	str = removeArgName(structString)
	if str != "struct shmid_ds *" {
		t.Errorf("Did not strip off uid")
	}

}
