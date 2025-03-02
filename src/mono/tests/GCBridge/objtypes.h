#pragma once

#include <stdint.h>

#define SGEN_GC_BIT_BRIDGE_OPAQUE_OBJECT 1

typedef struct {
    char *name;
} MonoClass;

typedef struct {
    MonoClass *klass;
    int gc_bits;
} MonoVTable;

typedef struct _MonoObject {
    MonoVTable *vtable;
    size_t lock_word;
    int is_alive;
    int ref_count;
    struct _MonoObject **refs;
} MonoObject;

typedef MonoObject GCObject;
typedef MonoVTable* GCVTable;
