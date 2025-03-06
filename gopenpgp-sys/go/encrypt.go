package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"

//export pgp_encrypt
func pgp_encrypt(
	encryption_handle *C.PGP_CEncryptionHandle,
	message *C.cuchar_t,
	message_len C.size_t,
	encoding C.uchar_t,
	detached_sig *C.PGP_ExtWriter, // only considered if detached sig is enabled, can be null
	result_buffer C.PGP_ExtWriter,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	encryptor, err := handleToEncryptor(encryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize encryptor: %w", err))
	}
	goMessage := unsafe.Slice((*byte)(message), (C.int)(message_len))
	var extBufferWriter io.Writer
	extBufferWriter = PGPExtBufferWriter{buffer: result_buffer}

	// Avoid go unpinned memory error for large content.
	extBufferWriterBuffered := bufio.NewWriter(extBufferWriter)
	extBufferWriter = extBufferWriterBuffered
	defer func() {
		if err := extBufferWriterBuffered.Flush(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go flush: %v", err))
		}
	}()

	if bool(encryption_handle.detached_sig) {
		if encryption_handle.signing_keys_len == 0 {
			return errorToPGPError(fmt.Errorf("no signing keys provided"))
		}
		var extSigWriter io.Writer = PGPExtBufferWriter{buffer: *detached_sig}
		// Avoid go unpinned memory error for large content
		extBufferWriterBufferedSig := bufio.NewWriter(extSigWriter)
		extSigWriter = extBufferWriterBufferedSig
		defer func() {
			if err := extBufferWriterBufferedSig.Flush(); err != nil {
				cErr = errorToPGPError(fmt.Errorf("go flush: %v", err))
			}
		}()
		extBufferWriter = crypto.NewPGPSplitWriterDetachedSignature(extBufferWriter, extSigWriter)
	}
	ctWriter, err := encryptor.EncryptingWriter(extBufferWriter, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to prepare encryption stream: %w", err))
	}

	if _, err := io.Copy(ctWriter, bytes.NewReader(goMessage)); err != nil {
		return errorToPGPError(fmt.Errorf("failed to encrypt stream: %w", err))
	}

	if err := ctWriter.Close(); err != nil {
		return errorToPGPError(fmt.Errorf("failed to encrypt stream: %w", err))
	}
	return errorToPGPError(nil)
}

//export pgp_encrypt_stream
func pgp_encrypt_stream(
	encryption_handle *C.PGP_CEncryptionHandle,
	writer C.PGP_ExtWriter,
	detached_sig *C.PGP_ExtWriter, // only considered if detached sig is enabled, can be null
	encoding C.uchar_t,
	out_encryptor_writer *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	encryptor, err := handleToEncryptor(encryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize encryptor: %w", err))
	}
	var extWriter io.Writer = &PGPExtBufferCopyWriter{external: writer}
	if bool(encryption_handle.detached_sig) {
		if encryption_handle.signing_keys_len == 0 {
			return errorToPGPError(fmt.Errorf("no signing keys provided"))
		}
		var extSigWriter io.Writer = &PGPExtBufferCopyWriter{external: *detached_sig}
		extWriter = crypto.NewPGPSplitWriterDetachedSignature(extWriter, extSigWriter)
	}

	ctWriter, err := encryptor.EncryptingWriter(extWriter, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to prepare encryption stream: %w", err))
	}
	*out_encryptor_writer = C.uintptr_t(cgo.NewHandle(ctWriter))
	return errorToPGPError(nil)
}

//export pgp_encrypt_stream_split
func pgp_encrypt_stream_split(
	encryption_handle *C.PGP_CEncryptionHandle,
	writer C.PGP_ExtWriter,
	detached_sig *C.PGP_ExtWriter, // only considered if detached sig is enabled, can be null
	key_packet_buffer C.PGP_ExtWriter,
	out_encryptor_writer *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	encryptor, err := handleToEncryptor(encryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize encryptor: %w", err))
	}
	extWriter := &PGPExtBufferCopyWriter{external: writer}
	extKeyPacketWriter := PGPExtBufferWriter{buffer: key_packet_buffer}
	var outputWriter io.Writer
	if bool(encryption_handle.detached_sig) {
		if encryption_handle.signing_keys_len == 0 {
			return errorToPGPError(fmt.Errorf("no signing keys provided"))
		}
		extSigWriter := &PGPExtBufferCopyWriter{external: *detached_sig}
		outputWriter = crypto.NewPGPSplitWriter(extKeyPacketWriter, extWriter, extSigWriter)
	} else {
		outputWriter = crypto.NewPGPSplitWriterKeyAndData(extKeyPacketWriter, extWriter)
	}

	ctWriter, err := encryptor.EncryptingWriter(outputWriter, crypto.Bytes)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to prepare encryption stream: %w", err))
	}
	*out_encryptor_writer = C.uintptr_t(cgo.NewHandle(ctWriter))
	return errorToPGPError(nil)
}

//export pgp_encrypt_session_key
func pgp_encrypt_session_key(
	encryption_handle *C.PGP_CEncryptionHandle,
	session_key_handle C.uintptr_t,
	result_buffer C.PGP_ExtWriter,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	encryptor, err := handleToEncryptor(encryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize encryptor: %w", err))
	}
	goSessionKey := handleToSessionKey(session_key_handle)
	extBuffer := PGPExtBufferWriter{buffer: result_buffer}
	encryptedSessionKey, err := encryptor.EncryptSessionKey(goSessionKey)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to encrypt session key: %w", err))
	}
	if _, err := extBuffer.Write(encryptedSessionKey); err != nil {
		return errorToPGPError(fmt.Errorf("failed to write encrypted session key to external buffer: %w", err))
	}
	return errorToPGPError(nil)
}

//export pgp_message_new
func pgp_message_new(
	message *C.cuchar_t,
	message_len C.size_t,
	armored C.bool_t,
) C.uintptr_t {
	goMessage := unsafe.Slice((*byte)(message), (C.int)(message_len))
	if bool(armored) {
		// Creates copy
		unarmoredMessage, err := armor.UnarmorBytes(goMessage)
		if err == nil {
			goMessage = unarmoredMessage
		}

	}
	pgpMessage := crypto.NewPGPMessageWithCloneFlag(goMessage, false)
	return (C.uintptr_t)(cgo.NewHandle(pgpMessage))
}

//export pgp_message_get_enc_key_ids
func pgp_message_get_enc_key_ids(
	handle C.uintptr_t,
	out_key_ids **C.uint64_t,
	out_key_ids_len *C.size_t,
) {
	msg := handleToPGPMessage(handle)
	keyIDs, ok := msg.EncryptionKeyIDs()
	if !ok {
		*out_key_ids_len = 0
	}
	*out_key_ids_len = C.size_t(len(keyIDs))
	*out_key_ids = (*C.uint64_t)(C.malloc(C.size_t(len(keyIDs)) * C.sizeof_uint64_t))
	ptr := *out_key_ids
	for index := 0; index < len(keyIDs); index++ {
		loc := (*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(index*C.sizeof_uint64_t)))
		*loc = C.uint64_t(keyIDs[index])
	}
}

//export pgp_message_get_sig_key_ids
func pgp_message_get_sig_key_ids(
	handle C.uintptr_t,
	out_key_ids **C.uint64_t,
	out_key_ids_len *C.size_t,
) {
	msg := handleToPGPMessage(handle)
	keyIDs, ok := msg.SignatureKeyIDs()
	if !ok {
		*out_key_ids_len = 0
	}
	*out_key_ids_len = C.size_t(len(keyIDs))
	*out_key_ids = (*C.uint64_t)(C.malloc(C.size_t(len(keyIDs)) * C.sizeof_uint64_t))
	ptr := *out_key_ids
	for index := 0; index < len(keyIDs); index++ {
		loc := (*C.uint64_t)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(index*C.sizeof_uint64_t)))
		*loc = C.uint64_t(keyIDs[index])
	}
}

//export pgp_message_key_packet_split
func pgp_message_key_packet_split(
	handle C.uintptr_t,
) C.size_t {
	msg := handleToPGPMessage(handle)
	return C.size_t(len(msg.KeyPacket))
}

//export pgp_message_destroy
func pgp_message_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}
