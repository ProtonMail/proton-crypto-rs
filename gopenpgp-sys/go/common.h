#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef unsigned char uchar_t;
typedef const unsigned char cuchar_t;
typedef const char cchar_t;
typedef const uintptr_t cuintptr_t;
typedef char char_t;
typedef bool bool_t;
typedef char* charptr_t;

void free(void*);
typedef const void cvoid_t;

typedef struct {
  cchar_t* err;
  int err_len;
} PGP_Error;

typedef struct {
  size_t num;
  charptr_t* strings;
} PGP_StringArray;

#endif /* COMMON_H */
