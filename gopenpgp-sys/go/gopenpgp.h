#ifndef GOPENPGP_H
#define GOPENPGP_H

#include "common.h"

typedef enum Reader {
  READER_OK = 1,
  READER_ERROR = -1,
  READER_EOF = 1
} PGP_READER_CODES;

typedef enum Writer { WRITER_ERROR = -1 } PGP_WRITER_CODES;

typedef enum KeyGeneration {
  KEY_GEN_RSA = 1,
  KEY_GEN_ECC = 2
} PGP_KEY_GENERATION;

typedef enum Armor {
  ARMOR_MESSAGE = 0,
  ARMOR_SIGNATURE = 1,
  ARMOR_PRIV_KEY = 2,
  ARMOR_PUB_KEY = 3
} PGP_ARMOR_HEADER;

typedef enum DataEncoding { ARMOR = 0, BYTES = 1, AUTO = 2 } PGP_DATA_ENCODING;

typedef enum SymmetricCiphers {
  TRIPLE_DES = 2,
  CAST5 = 3,
  AES_128 = 7,
  AES_192 = 8,
  AES_256 = 9
} PGP_SYMMETRIC_CIPHERS;

typedef struct {
  size_t encryption_keys_len;
  size_t signing_keys_len;
  bool_t has_session_key;
  bool_t has_signing_context;
  bool_t has_encryption_time;
  bool_t detached_sig;
  bool_t detached_sig_encrypted;
  bool_t utf8;
  bool_t compress;
  cuintptr_t* encryption_keys;
  cuintptr_t* signing_keys;
  uintptr_t session_key;
  uintptr_t signing_context;
  uint64_t encryption_time;
  size_t password_len;
  cuchar_t* password;
} PGP_EncryptionHandle;
typedef const PGP_EncryptionHandle PGP_CEncryptionHandle;

typedef struct {
  size_t decryption_keys_len;
  size_t verification_keys_len;
  size_t password_len;
  size_t detached_sig_len;
  bool_t has_session_key;
  bool_t has_verification_context;
  bool_t has_verification_time;
  bool_t utf8;
  bool_t detached_sig_is_encrypted;
  bool_t detached_sig_armored;
  cuintptr_t* decryption_keys;
  cuintptr_t* verification_keys;
  uintptr_t session_key;
  uintptr_t verification_context;
  uint64_t verification_time;
  cuchar_t* password;
  cuchar_t* detached_sig;
} PGP_DecryptionHandle;
typedef const PGP_DecryptionHandle PGP_CDecryptionHandle;

typedef struct {
  size_t signing_keys_len;
  bool_t has_signing_context;
  bool_t has_sign_time;
  bool_t utf8;
  cuintptr_t* signing_keys;
  uintptr_t signing_context;
  uint64_t sign_time;
} PGP_SignHandle;
typedef const PGP_SignHandle PGP_CSignHandle;

typedef struct {
  size_t verification_keys_len;
  bool_t has_verification_time;
  bool_t has_verification_context;
  bool_t utf8;
  cuintptr_t* verification_keys;
  uintptr_t verification_context;
  uint64_t verification_time;
} PGP_VerificationHandle;
typedef const PGP_VerificationHandle PGP_CVerificationHandle;

typedef struct {
  void* ptr;
  int64_t (*write)(void*, const void*, size_t);
} PGP_ExtWriter;

static inline int64_t pgp_ext_buffer_write(PGP_ExtWriter* buffer,
                                           const void* ptr, size_t size) {
  return buffer->write(buffer->ptr, ptr, size);
}

typedef struct {
  void* ptr;
  int64_t (*read)(void*, void*, size_t, int*);
} PGP_ExtReader;

static inline int64_t pgp_ext_reader_read(PGP_ExtReader* reader, void* ptr,
                                          size_t size, int* error_code) {
  return reader->read(reader->ptr, ptr, size, error_code);
}

typedef struct {
  bool_t has_verification_result;
  uintptr_t verification_result;
  PGP_ExtWriter plaintext_buffer;
} PGP_PlaintextResult;
typedef const PGP_PlaintextResult PGP_CPlaintextResult;

typedef struct {
  uchar_t signature_type;
  uint64_t creation_time;
  uint64_t key_id;
  uchar_t* key_fingerprint;
  size_t key_fingerprint_len;
  uchar_t* selected_signature;
  size_t selected_signature_len;
} PGP_SignatureInfo;
typedef const PGP_SignatureInfo CPGP_SignatureInfo;

typedef struct {
  size_t number_of_signatures;
  uchar_t* all_signatures;
  size_t all_signatures_len;
} PGP_Signatures;
typedef const PGP_Signatures CPGP_Signatures;

typedef struct {
  bool_t has_generation_time;
  bool_t has_user_id;
  cchar_t* name;
  size_t name_len;
  cchar_t* email;
  size_t email_len;
  uint64_t generation_time;
  uchar_t algorithm;
} PGP_KeyGeneration;
typedef const PGP_KeyGeneration PGP_CPGP_KeyGeneration;

#endif /* GOPENPGP_H */
