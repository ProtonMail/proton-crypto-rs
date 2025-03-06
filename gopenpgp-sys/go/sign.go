package main

import (
	"bufio"
	"fmt"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"

//export pgp_signing_context_new
func pgp_signing_context_new(
	value *C.cchar_t,
	value_len C.size_t,
	is_critical C.bool_t,
) C.uintptr_t {
	goValue := C.GoStringN(value, (C.int)(value_len))
	verificationContext := crypto.NewSigningContext(goValue, bool(is_critical))
	return (C.uintptr_t)(cgo.NewHandle(verificationContext))
}

//export pgp_signing_context_new_destroy
func pgp_signing_context_new_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export pgp_sign
func pgp_sign(
	sing_handle *C.PGP_CSignHandle,
	data *C.cuchar_t,
	data_len C.size_t,
	encoding C.uchar_t,
	detached C.bool_t,
	result_buffer C.PGP_ExtWriter,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	signer, err := handleToSigner(sing_handle, bool(detached))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize signer: %w", err))
	}
	goData := unsafe.Slice((*byte)(data), (C.int)(data_len))
	extBuffer := PGPExtBufferWriter{buffer: result_buffer}
	// Buffered I/O due to cgo pin errors
	extBufferBuffered := bufio.NewWriter(extBuffer)
	ptWriter, err := signer.SigningWriter(extBufferBuffered, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature creation failed: %v", err))
	}
	if _, err := ptWriter.Write(goData); err != nil {
		return errorToPGPError(fmt.Errorf("signature creation failed while writing data: %v", err))
	}
	if err := ptWriter.Close(); err != nil {
		return errorToPGPError(fmt.Errorf("signature creation failed while signing: %v", err))
	}
	if err := extBufferBuffered.Flush(); err != nil {
		return errorToPGPError(fmt.Errorf("signature creation failed while writing data: %v", err))
	}
	return errorToPGPError(nil)
}

//export pgp_sign_cleartext
func pgp_sign_cleartext(
	sing_handle *C.PGP_CSignHandle,
	data *C.cuchar_t,
	data_len C.size_t,
	result_buffer C.PGP_ExtWriter,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	signer, err := handleToSigner(sing_handle, false)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize signer: %w", err))
	}
	goData := unsafe.Slice((*byte)(data), (C.int)(data_len))
	extBuffer := PGPExtBufferWriter{buffer: result_buffer}

	cleartext_message, err := signer.SignCleartext(goData)
	if err != nil {
		return errorToPGPError(fmt.Errorf("cleartext message creation failed: %v", err))
	}

	if _, err := extBuffer.Write(cleartext_message); err != nil {
		return errorToPGPError(fmt.Errorf("cleartext message creation failed while writing buffer: %v", err))
	}

	return errorToPGPError(nil)
}

//export pgp_sign_stream
func pgp_sign_stream(
	sing_handle *C.PGP_CSignHandle,
	writer C.PGP_ExtWriter,
	encoding C.uchar_t,
	detached C.bool_t,
	out_sign_writer *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	signer, err := handleToSigner(sing_handle, bool(detached))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize signer: %w", err))
	}
	extBuffer := &PGPExtBufferCopyWriter{external: writer}
	signWriter, err := signer.SigningWriter(extBuffer, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to prepare sign stream: %w", err))
	}
	*out_sign_writer = C.uintptr_t(cgo.NewHandle(signWriter))
	return errorToPGPError(nil)
}
