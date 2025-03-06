package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
)

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"

var pgp = crypto.PGPWithProfile(profile.ProtonV1())

//export pgp_armor_message
func pgp_armor_message(
	message *C.cuchar_t,
	message_len C.size_t,
	armor_type C.uchar_t,
	result_buffer C.PGP_ExtWriter,
) C.PGP_Error {
	messageGo := unsafe.Slice((*byte)(message), (C.int)(message_len))
	var header string
	switch armor_type {
	case C.ARMOR_MESSAGE:
		header = constants.PGPMessageHeader
	case C.ARMOR_SIGNATURE:
		header = constants.PGPSignatureHeader
	case C.ARMOR_PRIV_KEY:
		header = constants.PrivateKeyHeader
	case C.ARMOR_PUB_KEY:
		header = constants.PublicKeyHeader
	default:
		return errorToPGPError(fmt.Errorf("unsupported armor type"))
	}
	extBuffer := PGPExtBufferWriter{buffer: result_buffer}
	// Buffered I/O due to cgo pin errors
	buffered := bufio.NewWriter(extBuffer)
	writeCloser, err := armor.ArmorWriterWithType(buffered, header)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to armor: %w", err))
	}
	if _, err := io.Copy(writeCloser, bytes.NewReader(messageGo)); err != nil {
		return errorToPGPError(fmt.Errorf("failed to armor:  %w", err))
	}
	if err := writeCloser.Close(); err != nil {
		return errorToPGPError(fmt.Errorf("failed to armor:  %w", err))
	}
	if err := buffered.Flush(); err != nil {
		return errorToPGPError(fmt.Errorf("failed to armor:  %w", err))
	}
	return errorToPGPError(nil)
}

//export pgp_unarmor_message
func pgp_unarmor_message(
	message *C.cuchar_t,
	message_len C.size_t,
	result_buffer C.PGP_ExtWriter,
) C.PGP_Error {
	messageGo := unsafe.Slice((*byte)(message), (C.int)(message_len))
	extBuffer := PGPExtBufferWriter{buffer: result_buffer}
	// IMPROVEMENT: Avoid copy here by exposing a streaming function
	bytes, err := armor.UnarmorBytes(messageGo)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to unarmor: %w", err))
	}
	if _, err := extBuffer.Write(bytes); err != nil {
		return errorToPGPError(fmt.Errorf("failed to unarmor: %w", err))
	}
	return errorToPGPError(nil)
}

// ------------------------------- Streaming Utils ------------------------------------------------------------------

type PGPExtBufferWriter struct {
	buffer C.PGP_ExtWriter
}

func (p PGPExtBufferWriter) Write(data []byte) (n int, err error) {
	if len(data) < 1 {
		return 0, nil
	}
	dataPtr := unsafe.Pointer(&data[0])
	dataLen := (C.size_t)(len(data))
	r := C.pgp_ext_buffer_write(&p.buffer, dataPtr, dataLen)
	if r < 0 {
		return 0, fmt.Errorf("failed to write to external buffer")
	}
	n = (int)(r)
	if n < len(data) {
		// Write must return a non-nil error if it returns n < len(data)
		return n, errors.New("failed to write whole slice to external buffer")
	}
	return n, nil
}

type ExternalReader struct {
	external C.PGP_ExtReader
}

func NewExternalReader(external C.PGP_ExtReader) *ExternalReader {
	return &ExternalReader{external: external}
}

func (r *ExternalReader) Read(b []byte) (n int, err error) {
	if len(b) < 1 {
		return 0, nil
	}
	ptr := unsafe.Pointer(unsafe.Pointer(&b[0]))
	var code C.int
	read := C.pgp_ext_reader_read(&r.external, ptr, C.size_t(len(b)), &code)
	switch code {
	case C.READER_EOF:
		return int(read), io.EOF
	case C.READER_ERROR:
		return int(read), fmt.Errorf("error occurred while reading from external source")
	}
	return int(read), nil
}

//export pgp_verification_reader_read
func pgp_verification_reader_read(
	r C.uintptr_t,
	buffer *C.uchar_t,
	buffer_len C.size_t,
	data_read *C.size_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	reader := handleToVerifyReader(r)
	bufferSlice := unsafe.Slice((*byte)(buffer), (C.int)(buffer_len))
	n, err := reader.Read(bufferSlice)
	if err != nil && !errors.Is(err, io.EOF) {
		return errorToPGPError(err)
	}
	*data_read = C.size_t(n)
	return errorToPGPError(nil)
}

//export pgp_verification_reader_get_verify_result
func pgp_verification_reader_get_verify_result(
	handle C.uintptr_t,
	out_verification_result *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	reader := handleToVerifyReader(handle)
	result, err := reader.VerifySignature()
	if err != nil {
		return errorToPGPError(err)
	}
	*out_verification_result = (C.uintptr_t)(cgo.NewHandle(result))
	return errorToPGPError(nil)
}

//export pgp_go_reader_destroy
func pgp_go_reader_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export pgp_message_write_closer_write
func pgp_message_write_closer_write(
	w C.uintptr_t,
	buffer *C.cuchar_t,
	buffer_len C.size_t,
	data_written *C.size_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	writer := handleToWriteCloser(w)
	bufferSlice := unsafe.Slice((*byte)(buffer), (C.int)(buffer_len))
	n, err := writer.Write(bufferSlice)
	if err != nil {
		return errorToPGPError(err)
	}
	*data_written = C.size_t(n)
	return errorToPGPError(nil)
}

//export pgp_message_write_closer_close
func pgp_message_write_closer_close(
	w C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	writer := handleToWriteCloser(w)
	if err := writer.Close(); err != nil {
		return errorToPGPError(err)
	}
	return errorToPGPError(nil)
}

//export pgp_message_write_closer_destroy
func pgp_message_write_closer_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

const bufferSize = 4096

// PGPExtBufferCopyWriter warps an external writer
// and copies written data to an internal buffer before writing
// it to and external writer.
// The copies are done due to cgo pinning errors at runtime.
type PGPExtBufferCopyWriter struct {
	external C.PGP_ExtWriter
	buffer   [bufferSize]byte
}

func (p *PGPExtBufferCopyWriter) Write(data []byte) (n int, err error) {
	if len(data) < 1 {
		return 0, nil
	}
	var written int
	dataPtr := unsafe.Pointer(&p.buffer[0])
	for pos := 0; pos < len(data); pos += bufferSize {
		// Copy data to avoid cgo pinning errors at runtime for pgp_ext_buffer_write
		numCopied := copy(p.buffer[:], data[pos:])
		dataLen := (C.size_t)(numCopied)
		r := C.pgp_ext_buffer_write(&p.external, dataPtr, dataLen)
		if r < 0 {
			return 0, fmt.Errorf("failed to write to external buffer")
		}
		written += int(r)
		if int(r) < bufferSize {
			break
		}
	}
	if written != len(data) {
		// Write must return a non-nil error if it returns n < len(p)
		return written, errors.New("failed to write whole slice to external")
	}
	return written, nil
}
