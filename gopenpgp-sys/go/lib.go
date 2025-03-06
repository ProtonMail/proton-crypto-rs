package main

import (
	"unsafe"
)

/*
#include "common.h"
*/
import "C"

//export pgp_free
func pgp_free(ptr *C.void) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

//export pgp_cfree
func pgp_cfree(ptr *C.cvoid_t) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func sliceToCMem(slice []byte) (*C.uchar, C.size_t) {
	cBuf := C.CBytes(slice)
	return (*C.uchar)(cBuf), C.size_t(len(slice))
}

func stringCMem(value string) (*C.char_t, C.size_t) {
	cBuf := C.CString(value)
	return (*C.char_t)(cBuf), C.size_t(len(value))
}

func stringSliceCMem(values []string) C.PGP_StringArray {
	array := C.malloc(C.sizeof_charptr_t * C.size_t(len(values)))
	for index := 0; index < len(values); index++ {
		location := (*C.charptr_t)(unsafe.Pointer(uintptr(array) + uintptr(index*C.sizeof_charptr_t)))
		*location = C.CString(values[index])
	}
	return C.PGP_StringArray{C.size_t(len(values)), (*C.charptr_t)(array)}
}

func errorToPGPError(err error) C.PGP_Error {
	cerr := C.PGP_Error{
		err:     nil,
		err_len: 0,
	}
	if err != nil {
		str := err.Error()
		cerr.err = C.CString(str)
		cerr.err_len = C.int(len(str))
	}

	return cerr
}

func main() {}
