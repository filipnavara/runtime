#include "common.h"
#include "gcenv.h"
#include "gcheaputilities.h"
#include "gcbridge.h"
#include "thread.h"
#include "threadstore.h"
#include "threadstore.inl"

#define FEATURE_GC_BRIDGE

#define HAVE_SGEN_GC

#define DUMP_GRAPH 1

#define INTERNAL_MEM_BRIDGE_DATA 0xf00d
#define INTERNAL_MEM_TARJAN_OBJ_BUCKET 0xf00f
int bucket_size;
void* sgen_alloc_internal_dynamic (size_t size, int type, bool assert_on_failure) { return malloc(size); }
void sgen_free_internal_dynamic (void *addr, size_t size, int type) { free(addr); }
void* sgen_alloc_internal (int type)
{
    assert(type == INTERNAL_MEM_TARJAN_OBJ_BUCKET);
    return malloc(bucket_size);
}
void sgen_free_internal (void *addr, int type) { free(addr); }
void sgen_register_fixed_internal_mem_type (int type, size_t size)
{
    assert(type == INTERNAL_MEM_TARJAN_OBJ_BUCKET);
    bucket_size = size;
}
bool sgen_need_bridge_processing () { return true; }

#define g_assert assert
#define g_assertf(c, ...) assert(c)
#define g_error(...) assert(0)
#define gboolean BOOL
#define mono_bool int32_t

#define MONO_ZERO_LEN_ARRAY 0

typedef MethodTable MonoClass;
typedef Object MonoObject;
typedef Object GCObject;

#define MONO_BEGIN_DECLS
#define MONO_END_DECLS
#define NO_MONO_PUBLIB_TYPES
#include "../../../../native/public/mono/metadata/details/sgen-bridge-types.h"

typedef size_t mword;

#define SIZEOF_VOID_P sizeof(void*)

BOOL sgen_object_is_live(GCObject *obj)
{
    return GCHeapUtilities::GetGCHeap()->IsPromoted(obj);
}

#define MONO_DISABLE_WARNING(...)
#define MONO_RESTORE_WARNING

#define GUINTPTR_TO_UINT(x) ((unsigned int)(x))

static char class_name_buffer[32];
const char *m_class_get_name(MonoClass *klass)
{
    snprintf(class_name_buffer, sizeof(class_name_buffer), "[CLASS:0x%p]", klass);
    return class_name_buffer;
}

#define SGEN_LOG(...)

#define SGEN_OBJECT_IS_FORWARDED(obj) obj

typedef int64_t gint64;
#define GINT64_TO_SIZE(i) ((size_t)(i))

#define SGEN_TV_DECLARE(name) int64_t name
#define SGEN_TV_GETTIME(tv) tv = 0
#define SGEN_TV_ELAPSED(start,end) 0

#define mono_trace(...)

#define MIN(x, y) min((x), (y))

#define BIT_SBLK_UNUSED                     0x80000000
// BIT_SBLK_UNUSED but extended to platform word size
#define BIT_SBLK_UNUSED_MW ((size_t)BIT_SBLK_UNUSED << 32)

#include "../../../mono/mono/metadata/sgen-tarjan-bridge.c"

static SgenBridgeProcessor s_bridge_processor;

static void
free_callback_data (SgenBridgeProcessor *processor)
{
	int i;
	int num_sccs = processor->num_sccs;
	int num_xrefs = processor->num_xrefs;
	MonoGCBridgeSCC **api_sccs = processor->api_sccs;
	MonoGCBridgeXRef *api_xrefs = processor->api_xrefs;

	for (i = 0; i < num_sccs; ++i) {
		sgen_free_internal_dynamic (api_sccs [i],
				sizeof (MonoGCBridgeSCC) + sizeof (MonoObject*) * api_sccs [i]->num_objs,
				INTERNAL_MEM_BRIDGE_DATA);
	}
	sgen_free_internal_dynamic (api_sccs, sizeof (MonoGCBridgeSCC*) * num_sccs, INTERNAL_MEM_BRIDGE_DATA);
	sgen_free_internal_dynamic (api_xrefs, sizeof (MonoGCBridgeXRef) * num_xrefs, INTERNAL_MEM_BRIDGE_DATA);

	processor->num_sccs = 0;
	processor->api_sccs = NULL;
	processor->num_xrefs = 0;
	processor->api_xrefs = NULL;
}


ScanFunc* JavaInteropNative::m_PromoteFunc;
bool JavaInteropNative::m_BridgingInProgress;
bool JavaInteropNative::s_BridgeProcessorInitialized;
static SgenBridgeProcessor s_BridgeProcessor;
static void (*s_CrossReferences)(int num_sccs, MonoGCBridgeSCC **sccs, int num_xrefs, MonoGCBridgeXRef *xrefs);

void
JavaInteropNative::BeforeGcScanRoots(int condemned, bool is_bgc, bool is_concurrent)
{
    printf("JavaInteropNative::BeforeGcScanRoots\n");

    if (is_concurrent)
        return;

    assert(!m_BridgingInProgress);

    if (!s_BridgeProcessorInitialized)
    {
        sgen_tarjan_bridge_init(&s_BridgeProcessor);
        s_BridgeProcessorInitialized = true;
    }    

    m_BridgingInProgress = true;
    m_PromoteFunc = NULL;
    reset_data();
}

void
JavaInteropNative::GcScanRoots(ScanFunc* fn, int condemned, int max_gen, ScanContext* sc)
{
    printf("JavaInteropNative::GcScanRoots\n");

    if (!m_BridgingInProgress)
        return;

    if (sc->promotion)
    {
        // HACK: Steal the GCHeap::Promote reference so we can do late promotion
        m_PromoteFunc = fn;
    }
    else
    {
        // Relocate the processed data
        for (int i = 0; i < s_BridgeProcessor.num_sccs; i++)
            for (int j = 0; j < s_BridgeProcessor.api_sccs[i]->num_objs; j++)
                fn(&s_BridgeProcessor.api_sccs[i]->objs[j], sc, 0);
    }
}

void
JavaInteropNative::AfterGcScanRoots(_In_ ScanContext* sc)
{
    printf("JavaInteropNative::AfterGcScanRoots\n");

    if (m_BridgingInProgress && sc->promotion)
    {
        processing_stw_step();
        processing_build_callback_data(-1);

        // Do a late promotion of the bridged objects so they don't get on the
        // finalizer queue.
        int bridge_count = dyn_array_ptr_size(&registered_bridges);
    	for (int i = 0; i < bridge_count; ++i)
        {
	    	GCObject *bridge_object = (GCObject *)dyn_array_ptr_get(&registered_bridges, i);
            m_PromoteFunc(&bridge_object, sc, 0);
        }        
    }
}

void
JavaInteropNative::AfterRestartEE()
{
    printf("JavaInteropNative::AfterRestartEE\n");

    if (m_BridgingInProgress)
    {
        if (s_BridgeProcessor.num_sccs > 0 &&
            s_CrossReferences != NULL)
        {
            //Thread * pThread = ThreadStore::GetCurrentThread();
            //pThread->SetDoNotTriggerGc();

            s_CrossReferences(
                s_BridgeProcessor.num_sccs, s_BridgeProcessor.api_sccs,
                s_BridgeProcessor.num_xrefs, s_BridgeProcessor.api_xrefs);

            // TODO: Mark dead objects

            //pThread->ClearDoNotTriggerGc();
        }

        processing_after_callback(-1);

        free_callback_data(&s_BridgeProcessor);

        m_BridgingInProgress = false;
    }    
}

bool
JavaInteropNative::IsTrackedReference(_In_ Object * object)
{
    // If we are running the bridging process then keep the references unpromoted.
    // We will promote them later after computing the compressed ref graph of the
    // dead object tree.
    //
    // However, if the bridging process is not running for any reason then we want
    // to be act as if all the references are alive.
    if (!m_BridgingInProgress)
        return true;

    // Keep a reference for the bridge object for later processing in AfterGcScanRoots
    register_finalized_object(object);

    // NOTE: It would be nice to get the handle here instead of the object pointer.
    // We would be able to save that and skip the relocation in GcScanRoots. It would
    // also allow as passing the handle to the cross_references callback and marking
    // an object dead would be as simiple as freeing the handle (and updating the
    // internal bookkeeping dictionary).

    return false;
}

EXTERN_C void QCALLTYPE
RhRegisterCrossReferencesCallback(void (*cross_references)(int num_sccs, MonoGCBridgeSCC **sccs, int num_xrefs, MonoGCBridgeXRef *xrefs))
{
    s_CrossReferences = cross_references;
}
