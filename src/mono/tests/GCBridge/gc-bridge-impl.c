#include "sgen-bridge-types.h"

#define MONO_DISABLE_WARNING(...)
#define MONO_RESTORE_WARNING

typedef size_t mword;
#define SIZEOF_VOID_P sizeof(void*)
#define GUINTPTR_TO_UINT(x) ((unsigned int)(x))

#define SGEN_VTABLE_BITS_MASK 7

#define SGEN_TV_DECLARE(name) int64_t name
#define SGEN_TV_GETTIME(tv) tv = 0
#define SGEN_TV_ELAPSED(start,end) 0

#define SGEN_OBJECT_IS_FORWARDED(x) 0
#define SGEN_LOAD_VTABLE(o) (MonoVTable*)((size_t)o->vtable & ~SGEN_VTABLE_BITS_MASK)

#define SGEN_LOG(...)
#define mono_trace(...)

#define INTERNAL_MEM_BRIDGE_DATA 0xf00d
#define INTERNAL_MEM_TARJAN_OBJ_BUCKET 0xf00f
int bucket_size;
void* sgen_alloc_internal_dynamic (size_t size, int type, gboolean assert_on_failure) { return calloc(1, size); }
void sgen_free_internal_dynamic (void *addr, size_t size, int type) { free(addr); }
void* sgen_alloc_internal (int type)
{
    assert(type == INTERNAL_MEM_TARJAN_OBJ_BUCKET);
    return calloc(1, bucket_size);
}
void sgen_free_internal (void *addr, int type) { free(addr); }
void sgen_register_fixed_internal_mem_type (int type, size_t size)
{
    assert(type == INTERNAL_MEM_TARJAN_OBJ_BUCKET);
    bucket_size = size;
}
gboolean sgen_need_bridge_processing () { return 1; }
gboolean sgen_object_is_live (GCObject *o) { return o->is_alive; }

#define MIN(x, y) min((x), (y))

typedef void* SgenDescriptor;
#define sgen_obj_get_descriptor_safe(obj) NULL

#include "../../mono/metadata/sgen-tarjan-bridge.c"
