package main

import (
	"bytes"
	"fmt"
	"runtime/cgo"
	"unsafe"

	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

/*
#include "common.h"
#include "gopenpgp.h"
*/
import "C"

//export pgp_key_ring_new
func pgp_key_ring_new() C.uintptr_t {
	kr, err := crypto.NewKeyRing(nil)
	if err != nil {
		// This should always pass since we are not initializing any keys at this point
		panic(err)
	}

	return (C.uintptr_t)(cgo.NewHandle(kr))
}

//export pgp_key_ring_destroy
func pgp_key_ring_destroy(handle C.uintptr_t) {
	cgo.Handle(handle).Delete()
}

//export pgp_key_ring_add_key
func pgp_key_ring_add_key(kr C.uintptr_t, k C.uintptr_t) C.PGP_Error {
	keyRing := handleToKeyRing(kr)
	key := handleToKey(k)

	return errorToPGPError(keyRing.AddKey(key))
}

//export pgp_key_unlock_with_token
func pgp_key_unlock_with_token(
	keys *C.cuintptr_t,
	keys_len C.size_t,
	private_key *C.cuchar_t,
	private_key_len C.size_t,
	message *C.cuchar_t,
	message_len C.size_t,
	signature *C.cuchar_t,
	signature_len C.size_t,
	out_key *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	keyRing, err := handleListToKeyRing(keys, keys_len)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed create key ring: %w", err))
	}

	goMessage := unsafe.Slice((*byte)(message), (C.int)(message_len))
	goSignature := unsafe.Slice((*byte)(signature), (C.int)(signature_len))

	decryptor, err := pgp.Decryption().DecryptionKeys(keyRing).New()
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed create decryptor: %w", err))
	}

	decryptedData, err := decryptor.Decrypt(goMessage, crypto.Armor)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to decrypt: %w", err))
	}
	token := decryptedData.Bytes()

	verifier, err := pgp.Verify().VerificationKeys(keyRing).New()
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed create verifier: %w", err))
	}
	verifyResult, err := verifier.VerifyDetached(token, goSignature, crypto.Armor)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to verify token:%w", err))
	}
	if err := verifyResult.SignatureError(); err != nil {
		return errorToPGPError(fmt.Errorf("signature verification for token failed:%w", err))
	}

	privateKey := unsafe.Slice((*byte)(private_key), (C.int)(private_key_len))
	key, err := crypto.NewKeyFromReaderExplicit(bytes.NewReader(privateKey), crypto.Armor)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed construct private key: %w", err))
	}

	defer key.ClearPrivateParams()

	unlockedKey, err := key.Unlock(token)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to unlock: %w", err))
	}

	*out_key = (C.uintptr_t)(cgo.NewHandle(unlockedKey))

	return errorToPGPError(nil)
}

//export pgp_private_key_import
func pgp_private_key_import(
	private_key *C.cuchar_t,
	private_key_len C.size_t,
	passphrase *C.cuchar_t,
	passphrase_len C.size_t,
	encoding C.uchar_t,
	out_key *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	privateKey := unsafe.Slice((*byte)(private_key), (C.int)(private_key_len))
	key, err := crypto.NewKeyFromReaderExplicit(bytes.NewReader(privateKey), int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed construct private key: %w", err))
	}

	defer key.ClearPrivateParams()

	var goPassphrase []byte
	if passphrase_len > 0 {
		goPassphrase = unsafe.Slice((*byte)(passphrase), (C.int)(passphrase_len))
	}

	unlockedKey, err := key.Unlock(goPassphrase)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to unlock: %w", err))
	}

	*out_key = (C.uintptr_t)(cgo.NewHandle(unlockedKey))

	return errorToPGPError(nil)
}

//export pgp_public_key_import
func pgp_public_key_import(
	public_key *C.cuchar_t,
	public_key_len C.size_t,
	encoding C.uchar_t,
	out_key *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	publicKey := unsafe.Slice((*byte)(public_key), (C.int)(public_key_len))
	key, err := crypto.NewKeyFromReaderExplicit(bytes.NewReader(publicKey), int8(encoding))
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to import public key: %w", err))
	}
	if key.IsPrivate() {
		key, err = key.ToPublic()
		if err != nil {
			return errorToPGPError(fmt.Errorf("failed to import public: %w", err))
		}
	}

	*out_key = (C.uintptr_t)(cgo.NewHandle(key))
	return errorToPGPError(nil)
}

//export pgp_private_key_get_public_key
func pgp_private_key_get_public_key(
	private_key C.uintptr_t,
	out_key *C.uintptr_t,
) C.PGP_Error {
	key := handleToKey(private_key)
	if !key.IsPrivate() {
		return errorToPGPError(fmt.Errorf("input key is not a private key"))
	}
	publicKey, err := key.ToPublic()
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to import public: %w", err))
	}
	*out_key = (C.uintptr_t)(cgo.NewHandle(publicKey))
	return errorToPGPError(nil)
}

//export pgp_key_export
func pgp_key_export(
	key C.uintptr_t,
	force_public C.bool_t,
	armored C.bool_t,
	out_buffer C.PGP_ExtWriter,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	goKey := handleToKey(key)
	extBuffer := PGPExtBufferWriter{buffer: out_buffer}
	var goKeyBytes []byte
	var err error
	if bool(force_public) && goKey.IsPrivate() {
		goKeyBytes, err = goKey.GetPublicKey()
	} else {
		goKeyBytes, err = goKey.Serialize()
	}
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to export key: %w", err))
	}

	if armored {
		header := constants.PublicKeyHeader
		if goKey.IsPrivate() && !bool(force_public) {
			header = constants.PrivateKeyHeader
		}
		goKeyBytes, err = armor.ArmorWithTypeBytes(goKeyBytes, header)
		if err != nil {
			return errorToPGPError(fmt.Errorf("failed to armor key: %w", err))
		}
	}
	if _, err := extBuffer.Write(goKeyBytes); err != nil {
		return errorToPGPError(fmt.Errorf("failed to export key: %w", err))
	}
	return errorToPGPError(nil)
}

//export pgp_key_get_version
func pgp_key_get_version(
	key C.uintptr_t,
) C.int {
	return C.int(handleToKey(key).GetVersion())
}

//export pgp_key_get_key_id
func pgp_key_get_key_id(
	key C.uintptr_t,
) C.uint64_t {
	return C.uint64_t(handleToKey(key).GetKeyID())
}

//export pgp_key_get_fingerprint_bytes
func pgp_key_get_fingerprint_bytes(
	key C.uintptr_t,
	out_fingerprint **C.uchar_t,
	out_fingerprint_len *C.size_t,
) {
	fingerprint := handleToKey(key).GetFingerprintBytes()
	*out_fingerprint, *out_fingerprint_len = sliceToCMem(fingerprint)
}

//export pgp_key_get_sha256_fingerprints
func pgp_key_get_sha256_fingerprints(
	key C.uintptr_t,
) C.PGP_StringArray {
	fingerprints := handleToKey(key).GetSHA256Fingerprints()
	return stringSliceCMem(fingerprints)
}

//export pgp_key_can_encrypt
func pgp_key_can_encrypt(
	key C.uintptr_t,
	time C.uint64_t,
) C.bool_t {
	return C.bool_t(handleToKey(key).CanEncrypt(int64(time)))
}

//export pgp_key_can_verify
func pgp_key_can_verify(
	key C.uintptr_t,
	time C.uint64_t,
) C.bool_t {
	return C.bool_t(handleToKey(key).CanVerify(int64(time)))
}

//export pgp_key_is_expired
func pgp_key_is_expired(
	key C.uintptr_t,
	time C.uint64_t,
) C.bool_t {
	return C.bool_t(handleToKey(key).IsExpired(int64(time)))
}

//export pgp_key_is_revoked
func pgp_key_is_revoked(
	key C.uintptr_t,
	time C.uint64_t,
) C.bool_t {
	return C.bool_t(handleToKey(key).IsRevoked(int64(time)))
}

//export pgp_key_lock
func pgp_key_lock(
	key C.uintptr_t,
	passphrase *C.cuchar_t,
	passphrase_len C.size_t,
	out_locked_key *C.uintptr_t,
) C.PGP_Error {
	passphraseGo := unsafe.Slice((*byte)(passphrase), (C.int)(passphrase_len))
	lockedKey, err := pgp.LockKey(handleToKey(key), passphraseGo)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed lock key: %w", err))
	}
	*out_locked_key = (C.uintptr_t)(cgo.NewHandle(lockedKey))
	return errorToPGPError(nil)
}

//export pgp_key_destroy
func pgp_key_destroy(k C.uintptr_t) {
	key := handleToKey(k)
	key.ClearPrivateParams()
	cgo.Handle(k).Delete()
}

// ------------------------------- Session Key ----------------------------------------------------------------------

func algorithmToStrID(algorithm C.PGP_SYMMETRIC_CIPHERS) string {
	var goAlgorithm string
	switch algorithm {
	case C.CAST5:
		goAlgorithm = constants.CAST5
	case C.TRIPLE_DES:
		goAlgorithm = constants.TripleDES
	case C.AES_128:
		goAlgorithm = constants.AES128
	case C.AES_192:
		goAlgorithm = constants.AES192
	default:
		goAlgorithm = constants.AES256
	}
	return goAlgorithm
}

//export pgp_new_session_key_from_token
func pgp_new_session_key_from_token(
	token *C.cuchar_t,
	token_len C.size_t,
	algorithm C.PGP_SYMMETRIC_CIPHERS,
) C.uintptr_t {
	goToken := unsafe.Slice((*byte)(token), (C.int)(token_len))
	goAlgorithm := algorithmToStrID(algorithm)
	// NewSessionKeyFromToken clones the goToken.
	sessionKey := crypto.NewSessionKeyFromToken(goToken, goAlgorithm)
	return (C.uintptr_t)(cgo.NewHandle(sessionKey))
}

//export pgp_generate_session_key
func pgp_generate_session_key(
	algorithm C.PGP_SYMMETRIC_CIPHERS,
	out_session_key *C.uintptr_t,
) (cErr C.PGP_Error) {
	defer func() {
		if err := recover(); err != nil {
			cErr = errorToPGPError(fmt.Errorf("go panic: %v", err))
		}
	}()
	goAlgorithm := algorithmToStrID(algorithm)
	sessionKey, err := crypto.GenerateSessionKeyAlgo(goAlgorithm)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed create decryptor: %w", err))
	}
	*out_session_key = (C.uintptr_t)(cgo.NewHandle(sessionKey))
	return errorToPGPError(nil)
}

//export pgp_session_key_export_token
func pgp_session_key_export_token(
	handle C.uintptr_t,
	out_token **C.uchar_t,
	out_token_len *C.size_t,
) {
	sessionKey := handleToSessionKey(handle)
	data := sessionKey.Key
	*out_token, *out_token_len = sliceToCMem(data)
}

//export pgp_session_key_get_algorithm
func pgp_session_key_get_algorithm(
	handle C.uintptr_t,
	out_code *C.uchar_t,
) C.PGP_Error {
	sessionKey := handleToSessionKey(handle)
	data, err := sessionKey.GetCipherFunc()
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed lock key: %w", err))
	}
	*out_code = C.uchar_t(int8(data))
	return errorToPGPError(nil)
}

//export pgp_session_key_destroy
func pgp_session_key_destroy(handle C.uintptr_t) {
	sessionKey := handleToSessionKey(handle)
	sessionKey.Clear()
	cgo.Handle(handle).Delete()
}

//export pgp_generate_key
func pgp_generate_key(
	key_generation_handle *C.PGP_CPGP_KeyGeneration,
	out_key_handle *C.uintptr_t,
) C.PGP_Error {
	keyGenerator, err := handleToKeyGenerator(key_generation_handle)
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to create key generation handle: %w", err))
	}
	goKey, err := keyGenerator.GenerateKey()
	if err != nil {
		return errorToPGPError(fmt.Errorf("failed to generate key: %w", err))
	}
	*out_key_handle = (C.uintptr_t)(cgo.NewHandle(goKey))
	return errorToPGPError(nil)
}
