package main

import (
	"errors"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"

func handleToKeyRing(handle C.uintptr_t) *crypto.KeyRing {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve KeyRing handle")
	}

	kr, ok := v.(*crypto.KeyRing)
	if !ok {
		panic("handle does not contain a KeyRing")
	}

	return kr
}

func handleToSessionKey(handle C.uintptr_t) *crypto.SessionKey {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve VerificationContext handle")
	}

	sessionKey, ok := v.(*crypto.SessionKey)
	if !ok {
		panic("handle does not contain a VerificationContext")
	}

	return sessionKey
}

func handleToVerificationContext(handle C.uintptr_t) *crypto.VerificationContext {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve VerificationContext handle")
	}

	vc, ok := v.(*crypto.VerificationContext)
	if !ok {
		panic("handle does not contain a VerificationContext")
	}

	return vc
}

func handleToSigningContext(handle C.uintptr_t) *crypto.SigningContext {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve SigningContext handle")
	}

	sc, ok := v.(*crypto.SigningContext)
	if !ok {
		panic("handle does not contain a SigningContext")
	}

	return sc
}

func handleToKey(handle C.uintptr_t) *crypto.Key {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve Key handle")
	}

	kr, ok := v.(*crypto.Key)
	if !ok {
		panic("handle does not contain a Key")
	}

	return kr
}

func handleToVerifyReader(handle C.uintptr_t) *crypto.VerifyDataReader {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve reader handle")
	}

	reader, ok := v.(*crypto.VerifyDataReader)
	if !ok {
		panic("handle does not contain a go reader")
	}

	return reader
}

func handleToWriteCloser(handle C.uintptr_t) crypto.WriteCloser {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve writer handle")
	}

	writeCloser, ok := v.(crypto.WriteCloser)
	if !ok {
		panic("handle does not contain a go writer")
	}

	return writeCloser
}

func handleListToKeyRing(handles *C.uintptr_t, num_handles C.size_t) (*crypto.KeyRing, error) {
	keyring, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for index := 0; index < int(num_handles); index++ {
		key := handleInListToKey(handles, index)
		if err := keyring.AddKey(key); err != nil {
			return nil, err
		}
	}
	return keyring, nil
}

func handleInListToKey(handles *C.uintptr_t, index int) *crypto.Key {
	// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block, gitlab.gosec.G103-1
	handle := *(*C.uintptr_t)(unsafe.Pointer(uintptr(unsafe.Pointer(handles)) + uintptr(index*C.sizeof_uintptr_t)))
	return handleToKey(handle)
}

func handleToVerificationResult(handle C.uintptr_t) *crypto.VerifyResult {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve VerifyResult handle")
	}

	vr, ok := v.(*crypto.VerifyResult)
	if !ok {
		panic("handle does not contain a VerifyResult")
	}

	return vr
}

func handleToPGPMessage(handle C.uintptr_t) *crypto.PGPMessage {
	v := cgo.Handle(handle).Value()
	if v == nil {
		panic("could not resolve PGPMessage handle")
	}

	m, ok := v.(*crypto.PGPMessage)
	if !ok {
		panic("handle does not contain a PGPMessage")
	}

	return m
}

func handleToDecryptor(handle *C.PGP_CDecryptionHandle) (crypto.PGPDecryption, error) {
	decryptorBuilder := pgp.Decryption()
	decryptorBuilder.DisableAutomaticTextSanitize()
	decryptorBuilder.DisableStrictMessageParsing()
	decryptorBuilder.DisableIntendedRecipients()
	if handle.decryption_keys_len > 0 {
		if handle.decryption_keys_len == 1 {
			key := handleInListToKey(handle.decryption_keys, 0)
			decryptorBuilder.DecryptionKey(key)
		} else {
			keyRing, err := handleListToKeyRing(handle.decryption_keys, handle.decryption_keys_len)
			if err != nil {
				return nil, errors.New("failed to create key ring: check that keys are unlocked")
			}
			decryptorBuilder.DecryptionKeys(keyRing)
		}
	}
	if handle.verification_keys_len > 0 {
		if handle.verification_keys_len == 1 {
			key := handleInListToKey(handle.verification_keys, 0)
			decryptorBuilder.VerificationKey(key)
		} else {
			keyRing, err := handleListToKeyRing(handle.verification_keys, handle.verification_keys_len)
			if err != nil {
				return nil, errors.New("failed to create key ring: check that keys are unlocked")
			}
			decryptorBuilder.VerificationKeys(keyRing)
		}
	}
	if bool(handle.has_session_key) {
		sessionKey := handleToSessionKey(handle.session_key)
		decryptorBuilder.SessionKey(sessionKey)
	}
	if C.int(handle.password_len) > 0 {
		// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block, gitlab.gosec.G103-1
		goPassword := unsafe.Slice((*byte)(handle.password), (C.int)(handle.password_len))
		decryptorBuilder.Password(goPassword)
	}
	if bool(handle.has_verification_context) {
		verificationContext := handleToVerificationContext(handle.verification_context)
		decryptorBuilder.VerificationContext(verificationContext)
	}
	if bool(handle.has_verification_time) {
		decryptorBuilder.VerifyTime(int64(handle.verification_time))
	}
	if bool(handle.utf8) {
		decryptorBuilder.Utf8()
	}
	if handle.detached_sig_len > 0 && !handle.detached_sig_is_encrypted {
		decryptorBuilder.PlainDetachedSignature()
	}
	return decryptorBuilder.New()
}

func handleToEncryptor(handle *C.PGP_CEncryptionHandle) (crypto.PGPEncryption, error) {
	encryptorBuilder := pgp.Encryption()
	// Allow to encrypt with keys in the future
	encryptorBuilder.EncryptionTime(0)
	if handle.encryption_keys_len > 0 {
		if handle.encryption_keys_len == 1 {
			key := handleInListToKey(handle.encryption_keys, 0)
			encryptorBuilder.Recipient(key)
		} else {
			keyRing, err := handleListToKeyRing(handle.encryption_keys, handle.encryption_keys_len)
			if err != nil {
				return nil, errors.New("failed to create key ring: check that keys are unlocked")
			}
			encryptorBuilder.Recipients(keyRing)
		}
	}
	if handle.signing_keys_len > 0 {
		if handle.signing_keys_len == 1 {
			key := handleInListToKey(handle.signing_keys, 0)
			encryptorBuilder.SigningKey(key)
		} else {
			keyRing, err := handleListToKeyRing(handle.signing_keys, handle.signing_keys_len)
			if err != nil {
				return nil, errors.New("failed to create key ring: check that keys are unlocked")
			}
			encryptorBuilder.SigningKeys(keyRing)
		}
	}
	if bool(handle.has_session_key) {
		sessionKey := handleToSessionKey(handle.session_key)
		encryptorBuilder.SessionKey(sessionKey)
	}
	if C.int(handle.password_len) > 0 {
		// nosemgrep: go.lang.security.audit.unsafe.use-of-unsafe-block, gitlab.gosec.G103-1
		goPassword := unsafe.Slice((*byte)(handle.password), (C.int)(handle.password_len))
		encryptorBuilder.Password(goPassword)
	}
	if bool(handle.has_signing_context) {
		signingContext := handleToSigningContext(handle.signing_context)
		encryptorBuilder.SigningContext(signingContext)
	}
	if bool(handle.has_encryption_time) {
		encryptorBuilder.SignTime(int64(handle.encryption_time))
	}
	if bool(handle.compress) {
		encryptorBuilder.Compress()
	}
	if bool(handle.utf8) {
		encryptorBuilder.Utf8()
	}
	if bool(handle.detached_sig) {
		if bool(handle.detached_sig_encrypted) {
			encryptorBuilder.DetachedSignature()
		} else {
			encryptorBuilder.PlainDetachedSignature()
		}
	}
	return encryptorBuilder.New()
}

func handleToVerifier(handle *C.PGP_CVerificationHandle) (crypto.PGPVerify, error) {
	verifierBuilder := pgp.Verify()
	verifierBuilder.DisableStrictMessageParsing()
	verifierBuilder.DisableAutomaticTextSanitize()
	if handle.verification_keys_len > 0 {
		if handle.verification_keys_len == 1 {
			key := handleInListToKey(handle.verification_keys, 0)
			verifierBuilder.VerificationKey(key)
		} else {
			keyRing, err := handleListToKeyRing(handle.verification_keys, handle.verification_keys_len)
			if err != nil {
				return nil, errors.New("failed to create key ring: check that keys are unlocked")
			}
			verifierBuilder.VerificationKeys(keyRing)
		}
	}
	if bool(handle.has_verification_context) {
		verificationContext := handleToVerificationContext(handle.verification_context)
		verifierBuilder.VerificationContext(verificationContext)
	}
	if bool(handle.has_verification_time) {
		verifierBuilder.VerifyTime(int64(handle.verification_time))
	}
	return verifierBuilder.New()
}

func handleToSigner(handle *C.PGP_CSignHandle, detached bool) (crypto.PGPSign, error) {
	signerBuilder := pgp.Sign()
	if handle.signing_keys_len > 0 {
		if handle.signing_keys_len == 1 {
			key := handleInListToKey(handle.signing_keys, 0)
			signerBuilder.SigningKey(key)
		} else {
			keyRing, err := handleListToKeyRing(handle.signing_keys, handle.signing_keys_len)
			if err != nil {
				return nil, errors.New("failed to create key ring: check that keys are unlocked")
			}
			signerBuilder.SigningKeys(keyRing)
		}
	}
	if bool(handle.has_signing_context) {
		signingContext := handleToSigningContext(handle.signing_context)
		signerBuilder.SigningContext(signingContext)
	}
	if bool(handle.has_sign_time) {
		signerBuilder.SignTime(int64(handle.sign_time))
	}
	if bool(handle.utf8) {
		signerBuilder.Utf8()
	}
	if detached {
		signerBuilder.Detached()
	}
	return signerBuilder.New()
}

func handleToKeyGenerator(handle *C.PGP_CPGP_KeyGeneration) (crypto.PGPKeyGeneration, error) {
	keyGenerationBuilder := pgp.KeyGeneration()
	if bool(handle.has_generation_time) {
		keyGenerationBuilder.GenerationTime(int64(handle.generation_time))
	}
	if bool(handle.has_user_id) {
		name := C.GoStringN(handle.name, (C.int)(handle.name_len))
		email := C.GoStringN(handle.email, (C.int)(handle.email_len))
		keyGenerationBuilder.AddUserId(name, email)
	}
	return keyGenerationBuilder.New(), nil
}
