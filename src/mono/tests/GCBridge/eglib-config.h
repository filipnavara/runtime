#include <stddef.h>
#include <sys/types.h>
#include <io.h>

#if defined(_MSC_VER)
#include <BaseTsd.h>
typedef SSIZE_T ssize_t;
#endif

typedef size_t gsize;
typedef ssize_t gssize;

#define G_GNUC_UNUSED
#define G_GSIZE_FORMAT "%zu"