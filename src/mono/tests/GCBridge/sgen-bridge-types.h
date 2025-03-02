#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "objtypes.h"

#define HAVE_SGEN_GC 1

#define g_assert assert
#define g_assertf(c, ...) assert(c)
#define g_error(...) assert(0)
#define gboolean int32_t
#define mono_bool int32_t
#define TRUE 1
#define FALSE 0
#define gint64 int64_t
#define GINT64_TO_SIZE(i) ((size_t)(i))
#define MONO_ZERO_LEN_ARRAY 0

#define MONO_BEGIN_DECLS
#define MONO_END_DECLS
#define NO_MONO_PUBLIB_TYPES
#include "../../../native/public/mono/metadata/details/sgen-bridge-types.h"

#include "../../mono/metadata/sgen-bridge-internals.h"

