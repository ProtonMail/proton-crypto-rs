package main

/*
#include "common.h"
*/
import "C"
import (
	"runtime/cgo"

	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

//export pgp_clone_session_key
func pgp_clone_session_key(
	session_key_handle C.uintptr_t,
) C.uintptr_t {
	sessionKey := handleToSessionKey(session_key_handle)
	clonedSessionKey := crypto.NewSessionKeyFromToken(sessionKey.Key, sessionKey.Algo)
	return (C.uintptr_t)(cgo.NewHandle(clonedSessionKey))
}

//export pgp_clone_key
func pgp_clone_key(
	key_handle C.uintptr_t,
	out_key_handle *C.uintptr_t,
) (cErr C.PGP_Error) {
	key := handleToKey(key_handle)
	clonedKey, err := key.Copy()
	if err != nil {
		// Does not happen if keys are immutable
		return errorToPGPError(err)
	}
	*out_key_handle = (C.uintptr_t)(cgo.NewHandle(clonedKey))
	return errorToPGPError(nil)
}

//export pgp_clone_signing_context
func pgp_clone_signing_context(
	signing_context C.uintptr_t,
) C.uintptr_t {
	ctx := handleToSigningContext(signing_context)
	clonedContext := crypto.NewSigningContext(ctx.Value, ctx.IsCritical)
	return (C.uintptr_t)(cgo.NewHandle(clonedContext))
}

//export pgp_clone_verification_context
func pgp_clone_verification_context(
	verification_context C.uintptr_t,
) C.uintptr_t {
	ctx := handleToVerificationContext(verification_context)
	clonedContext := crypto.NewVerificationContext(ctx.Value, ctx.IsRequired, ctx.RequiredAfter)
	return (C.uintptr_t)(cgo.NewHandle(clonedContext))
}
