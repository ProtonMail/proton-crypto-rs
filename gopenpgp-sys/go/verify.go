package main

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"
import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

//export pgp_verification_context_new
func pgp_verification_context_new(
	value *C.cchar_t,
	value_len C.size_t,
	is_required C.bool_t,
	required_after C.uint64_t,
) C.uintptr_t {
	goValue := C.GoStringN(value, (C.int)(value_len))
	verificationContext := crypto.NewVerificationContext(goValue, bool(is_required), int64(required_after))
	return (C.uintptr_t)(cgo.NewHandle(verificationContext))
}

//export pgp_verification_context_is_required
func pgp_verification_context_is_required(handle C.uintptr_t) C.bool_t {
	ctx := handleToVerificationContext(handle)
	return C.bool_t(ctx.IsRequired)
}

//export pgp_verification_context_is_required_after
func pgp_verification_context_is_required_after(handle C.uintptr_t) C.uint64_t {
	ctx := handleToVerificationContext(handle)
	return C.uint64_t(ctx.RequiredAfter)
}

//export pgp_verification_context_get_value
func pgp_verification_context_get_value(handle C.uintptr_t, value **C.char_t) {
	ctx := handleToVerificationContext(handle)
	*value, _ = stringCMem(ctx.Value)
}

//export pgp_verification_context_destroy
func pgp_verification_context_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export pgp_verification_result_error
func pgp_verification_result_error(handle C.uintptr_t, signature_status *C.int) C.PGP_Error {
	verifyResult := handleToVerificationResult(handle)
	signatureErr := verifyResult.SignatureErrorExplicit()
	if signatureErr != nil {
		*signature_status = C.int(signatureErr.Status)
		return errorToPGPError(fmt.Errorf("signature verification failed: %w", signatureErr))
	}
	*signature_status = C.int(constants.SIGNATURE_OK)
	return errorToPGPError(nil)
}

//export pgp_verification_result_signature_info
func pgp_verification_result_signature_info(handle C.uintptr_t, signature_info *C.PGP_SignatureInfo) C.PGP_Error {
	verifyResult := handleToVerificationResult(handle)
	creationTime := verifyResult.SignatureCreationTime()
	if len(verifyResult.Signatures) == 0 || creationTime == 0 {
		return errorToPGPError(fmt.Errorf("no signature found in message"))
	}
	fingerprint := verifyResult.SignedByFingerprint()
	selected_signature, err := verifyResult.Signature()
	if err != nil {
		return errorToPGPError(fmt.Errorf("serializing selected signature failed %w", err))
	}

	keyID := verifyResult.SignedByKeyId()
	signatureType := verifyResult.SignedWithTypeInt8()
	signature_info.creation_time = C.uint64_t(creationTime)
	signature_info.key_id = C.uint64_t(keyID)
	fingerprintC, fingerprintCLen := sliceToCMem(fingerprint)
	signature_info.key_fingerprint = fingerprintC
	signature_info.key_fingerprint_len = fingerprintCLen
	signature_info.signature_type = C.uchar_t(signatureType)
	selectedSigC, selectedSigCLen := sliceToCMem(selected_signature)
	signature_info.selected_signature = selectedSigC
	signature_info.selected_signature_len = selectedSigCLen
	return errorToPGPError(nil)
}

//export pgp_verification_result_all_signatures
func pgp_verification_result_all_signatures(handle C.uintptr_t, signatures *C.PGP_Signatures) C.PGP_Error {
	verifyResult := handleToVerificationResult(handle)
	var allSerializedSignatures bytes.Buffer
	for _, messageSignature := range verifyResult.Signatures {
		if err := messageSignature.Signature.Serialize(&allSerializedSignatures); err != nil {
			return errorToPGPError(fmt.Errorf("serializing signature failed %w", err))
		}
	}
	signatures.number_of_signatures = C.size_t(len(verifyResult.Signatures))
	if len(verifyResult.Signatures) > 0 {
		allSigC, allSigCLen := sliceToCMem(allSerializedSignatures.Bytes())
		signatures.all_signatures = allSigC
		signatures.all_signatures_len = allSigCLen
	}
	return errorToPGPError(nil)
}

//export pgp_verification_result_destroy
func pgp_verification_result_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export pgp_verify_detached
func pgp_verify_detached(
	verification_handle *C.PGP_CVerificationHandle,
	data *C.cuchar_t,
	data_len C.size_t,
	signature *C.cuchar_t,
	signature_len C.size_t,
	encoding C.uchar_t,
	verify_result *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	verifier, err := handleToVerifier(verification_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize verifier: %w", err))
	}
	goData := unsafe.Slice((*byte)(data), (C.int)(data_len))
	goSignature := unsafe.Slice((*byte)(signature), (C.int)(signature_len))
	verifyResult, err := verifier.VerifyDetached(goData, goSignature, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %v", err))
	}

	*verify_result = C.uintptr_t(cgo.NewHandle(verifyResult))
	return errorToPGPError(nil)
}

//export pgp_verify_detached_stream
func pgp_verify_detached_stream(
	verification_handle *C.PGP_CVerificationHandle,
	reader C.PGP_ExtReader,
	signature *C.cuchar_t,
	signature_len C.size_t,
	encoding C.uchar_t,
	verify_result *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	verifier, err := handleToVerifier(verification_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize verifier: %w", err))
	}
	goReader := NewExternalReader(reader)
	// Buffered I/O due to cgo pin errors
	goReaderBuffered := bufio.NewReader(goReader)
	goSignature := unsafe.Slice((*byte)(signature), (C.int)(signature_len))
	verifyResultReader, err := verifier.VerifyingReader(goReaderBuffered, bytes.NewReader(goSignature), int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %v", err))
	}

	verifyResult, err := verifyResultReader.DiscardAllAndVerifySignature()
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %v", err))
	}

	*verify_result = C.uintptr_t(cgo.NewHandle(verifyResult))
	return errorToPGPError(nil)
}

//export pgp_verify_cleartext
func pgp_verify_cleartext(
	verification_handle *C.PGP_CVerificationHandle,
	message *C.cuchar_t,
	message_len C.size_t,
	result *C.PGP_PlaintextResult,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	verifier, err := handleToVerifier(verification_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize verifier: %w", err))
	}
	goData := unsafe.Slice((*byte)(message), (C.int)(message_len))
	verifyResultData, err := verifier.VerifyCleartext(goData)
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %w", err))
	}

	extBuffer := PGPExtBufferWriter{buffer: result.plaintext_buffer}
	// no streaming support at the moment :(
	if _, err := extBuffer.Write(verifyResultData.Cleartext()); err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %w", err))
	}
	verifyResult := &verifyResultData.VerifyResult
	result.has_verification_result = C.bool_t(true)
	result.verification_result = C.uintptr_t(cgo.NewHandle(verifyResult))
	return errorToPGPError(nil)
}

//export pgp_verify_inline
func pgp_verify_inline(
	verification_handle *C.PGP_CVerificationHandle,
	message *C.cuchar_t,
	message_len C.size_t,
	encoding C.uchar_t,
	result *C.PGP_PlaintextResult,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	verifier, err := handleToVerifier(verification_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize verifier: %w", err))
	}
	goData := unsafe.Slice((*byte)(message), (C.int)(message_len))
	verifiedDataReader, err := verifier.VerifyingReader(nil, bytes.NewReader(goData), int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %w", err))
	}

	extBuffer := PGPExtBufferWriter{buffer: result.plaintext_buffer}
	if _, err := io.Copy(extBuffer, verifiedDataReader); err != nil {
		return errorToPGPError(fmt.Errorf("failed to decrypt stream: %w", err))
	}

	verificationResult, err := verifiedDataReader.VerifySignature()
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %w", err))
	}

	result.has_verification_result = C.bool_t(true)
	result.verification_result = C.uintptr_t(cgo.NewHandle(verificationResult))
	return errorToPGPError(nil)
}

//export pgp_verify_inline_stream
func pgp_verify_inline_stream(
	verification_handle *C.PGP_CVerificationHandle,
	reader C.PGP_ExtReader,
	encoding C.uchar_t,
	out_verification_reader *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	verifier, err := handleToVerifier(verification_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to initialize verifier: %w", err))
	}
	goReader := NewExternalReader(reader)
	// Buffered I/O due to cgo pin errors
	goReaderBuffered := bufio.NewReader(goReader)
	verifiedDataReader, err := verifier.VerifyingReader(nil, goReaderBuffered, int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("signature verification failed: %w", err))
	}
	*out_verification_reader = C.uintptr_t(cgo.NewHandle(verifiedDataReader))
	return errorToPGPError(nil)
}
