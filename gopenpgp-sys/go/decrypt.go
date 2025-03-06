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

//export pgp_decrypt
func pgp_decrypt(
	decryption_handle *C.PGP_CDecryptionHandle,
	body *C.cuchar_t,
	body_len C.size_t,
	encoding C.uchar_t,
	result *C.PGP_PlaintextResult,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	decryptor, err := handleToDecryptor(decryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize decryptor: %w", err))
	}
	goBody := unsafe.Slice((*byte)(body), (C.int)(body_len))

	detachedSignatureData, err := handleDetachedSignatureData(int8(encoding), decryption_handle)
	if err != nil {
		return errorToPGPError(err)
	}

	var goBodyReader io.Reader
	if detachedSignatureData != nil {
		goBodyReader = crypto.NewPGPSplitReader(bytes.NewReader(goBody), bytes.NewReader(detachedSignatureData))
	} else {
		goBodyReader = bytes.NewReader(goBody)
	}

	plaintextReader, err := decryptor.DecryptingReader(goBodyReader, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to prepare decryption stream: %w", err))
	}
	extBuffer := PGPExtBufferWriter{buffer: result.plaintext_buffer}

	if _, err := io.Copy(extBuffer, plaintextReader); err != nil {
		return errorToPGPError(fmt.Errorf("failed to decrypt stream: %w", err))
	}

	verificationResult, err := plaintextReader.VerifySignature()
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %v", err))
	}
	result.has_verification_result = C.bool_t(true)
	result.verification_result = C.uintptr_t(cgo.NewHandle(verificationResult))

	return errorToPGPError(nil)
}

//export pgp_decrypt_stream
func pgp_decrypt_stream(
	decryption_handle *C.PGP_CDecryptionHandle,
	reader C.PGP_ExtReader,
	encoding C.uchar_t,
	out_verification_reader *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	decryptor, err := handleToDecryptor(decryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize decryptor: %w", err))
	}

	detachedSignatureData, err := handleDetachedSignatureData(int8(encoding), decryption_handle)
	if err != nil {
		return errorToPGPError(err)
	}

	goReader := NewExternalReader(reader)
	// Buffered I/O due to cgo pin errors
	goReaderBuffered := bufio.NewReader(goReader)
	var goBodyReader io.Reader
	if detachedSignatureData != nil {
		goBodyReader = crypto.NewPGPSplitReader(goReaderBuffered, bytes.NewReader(detachedSignatureData))
	} else {
		goBodyReader = goReaderBuffered
	}
	plaintextReader, err := decryptor.DecryptingReader(goBodyReader, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to prepare decryption stream: %w", err))
	}

	*out_verification_reader = C.uintptr_t(cgo.NewHandle(plaintextReader))
	return errorToPGPError(nil)
}

//export pgp_decrypt_session_key
func pgp_decrypt_session_key(
	decryption_handle *C.PGP_CDecryptionHandle,
	key_packets *C.cuchar_t,
	key_packets_len C.size_t,
	out_session_key *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	decryptor, err := handleToDecryptor(decryption_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize decryptor: %w", err))
	}
	goKeyPackets := unsafe.Slice((*byte)(key_packets), (C.int)(key_packets_len))
	sessionKey, err := decryptor.DecryptSessionKey(goKeyPackets)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to decrypt session key: %w", err))
	}
	*out_session_key = C.uintptr_t(cgo.NewHandle(sessionKey))
	return errorToPGPError(nil)
}

//export pgp_decryption_result_destroy
func pgp_decryption_result_destroy(result *C.PGP_PlaintextResult) {
	if bool(result.has_verification_result) {
		cgo.Handle(result.verification_result).Delete()
	}
}

func handleDetachedSignatureData(inputDataEncoding int8, decryptionHandle *C.PGP_CDecryptionHandle) (detachedSignatureData []byte, err error) {
	if decryptionHandle.detached_sig_len == 0 {
		return nil, nil
	}
	// Handle detached signature of the plaintext data, which might be encrypted
	detachedSignatureData = unsafe.Slice((*byte)(decryptionHandle.detached_sig), (C.int)(decryptionHandle.detached_sig_len))

	// Handle the case where the content encoding is different than the signature encoding
	if decryptionHandle.detached_sig_armored && inputDataEncoding == crypto.Bytes {
		detachedSignatureData, err = armor.UnarmorBytes(detachedSignatureData)
		if err != nil {
			return nil, fmt.Errorf("failed unarmor detached signature: %w", err)
		}
	} else if !decryptionHandle.detached_sig_armored && inputDataEncoding == crypto.Armor {
		detachedSignatureData, err = armor.ArmorPGPSignatureBinary(detachedSignatureData)
		if err != nil {
			return nil, fmt.Errorf("failed armor detached signature: %w", err)
		}
	}
	return detachedSignatureData, nil
}
