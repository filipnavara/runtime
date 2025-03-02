#include <assert.h>
#include "sgen-bridge-types.h"

static MonoClass klass_RunnableImplementor = { .name = "RunnableImplementor" };
static MonoClass klass_ByteArrayOutputStream = { .name = "ByteArrayOutputStream" };
static MonoClass klass_AsyncStreamWriter = { .name = "<AsyncStreamWriter>d__2" };
static MonoClass klass_AsyncStateMachineBox = { .name = "AsyncStateMachineBox`1" };
static MonoClass klass_Action = { .name = "Action" };
static MonoClass klass_DisplayClass = { .name = "<>c__DisplayClass2_0" };

static MonoClass klass_Bridagable = { .name = "Bridagble" };
static MonoClass klass_NonBridagable = { .name = "NonBridagble" };

MonoObject *alloc_object(MonoClass *klass, int ref_count)
{
    MonoVTable *vtable = (MonoVTable *)malloc(sizeof(MonoVTable));
    vtable->klass = klass;
    vtable->gc_bits = 0;
    MonoObject *o = (MonoObject *)malloc(sizeof(MonoObject) + (ref_count * sizeof(MonoObject *)));
    o->vtable = vtable;
    o->vtable_copy = vtable;
    o->lock_word = 0;
    o->is_alive = FALSE;
    o->ref_count = ref_count;
    o->refs = (MonoObject **)(o + 1);
    memset(o->refs, 0, ref_count * sizeof(MonoObject *));
    return o;
}

static void
dump_processor_state (SgenBridgeProcessor *p)
{
	int i;

	printf ("------\n");
	printf ("SCCS %d\n", p->num_sccs);
	for (i = 0; i < p->num_sccs; ++i) {
		int j;
		MonoGCBridgeSCC *scc = p->api_sccs [i];
		printf ("\tSCC %d:", i);
		for (j = 0; j < scc->num_objs; ++j) {
			MonoObject *obj = scc->objs [j];
			printf (" %p(%s)", obj, obj->vtable->klass->name);
		}
		printf ("\n");
	}

	printf ("XREFS %d\n", p->num_xrefs);
	for (i = 0; i < p->num_xrefs; ++i)
		printf ("\t%d -> %d\n", p->api_xrefs [i].src_scc_index, p->api_xrefs [i].dst_scc_index);

	printf ("-------\n");
}

static void
free_callback_data (SgenBridgeProcessor *processor)
{
	for (int i = 0; i < processor->num_sccs; ++i)
		free (processor->api_sccs[i]);

    free (processor->api_sccs);
    free (processor->api_xrefs);

	processor->num_sccs = 0;
	processor->api_sccs = NULL;
	processor->num_xrefs = 0;
	processor->api_xrefs = NULL;
}


void test1(SgenBridgeProcessor *bridge_processor)
{
    bridge_processor->reset_data();

    MonoObject *o_runnableImplementor = alloc_object(&klass_RunnableImplementor, 1);
    MonoObject *o_byteArrayOutputStream = alloc_object(&klass_ByteArrayOutputStream, 0);
    MonoObject *o_action = alloc_object(&klass_Action, 2);
    MonoObject *o_displayClass = alloc_object(&klass_DisplayClass, 1);
    MonoObject *o_asyncStateMachineBox = alloc_object(&klass_AsyncStateMachineBox, 2);
    MonoObject *o_asyncStreamWriter = alloc_object(&klass_AsyncStreamWriter, 2);
    o_runnableImplementor->refs[0] = o_action;
    o_action->refs[0] = o_displayClass;
    o_action->refs[1] = o_asyncStateMachineBox;
    o_displayClass->refs[0] = o_action;
    o_asyncStateMachineBox->refs[0] = o_asyncStreamWriter;
    o_asyncStateMachineBox->refs[1] = o_action;
    o_asyncStreamWriter->refs[0] = o_byteArrayOutputStream;
    o_asyncStreamWriter->refs[1] = o_asyncStateMachineBox;

    bridge_processor->register_finalized_object(o_byteArrayOutputStream);
    bridge_processor->register_finalized_object(o_runnableImplementor);
    bridge_processor->processing_stw_step();
    bridge_processor->processing_build_callback_data(0);
    //dump_processor_state(&bridge_processor);
    assert(bridge_processor->num_sccs == 2);
    assert(bridge_processor->num_xrefs == 1);
    bridge_processor->processing_after_callback(0);
    free_callback_data(bridge_processor);
}


void test2(SgenBridgeProcessor *bridge_processor)
{
    bridge_processor->reset_data();

    MonoObject *o_runnableImplementor = alloc_object(&klass_RunnableImplementor, 1);
    MonoObject *o_runnableImplementor2 = alloc_object(&klass_RunnableImplementor, 1);
    MonoObject *o_runnableImplementor3 = alloc_object(&klass_RunnableImplementor, 1);
    MonoObject *o_byteArrayOutputStream = alloc_object(&klass_ByteArrayOutputStream, 0);

    MonoObject *o_action = alloc_object(&klass_Action, 100 * 2);
    for (int i = 0; i < 100; i++)
    {
        MonoObject *o_displayClass = alloc_object(&klass_DisplayClass, 1);
        MonoObject *o_asyncStateMachineBox = alloc_object(&klass_AsyncStateMachineBox, 2);
        MonoObject *o_asyncStreamWriter = alloc_object(&klass_AsyncStreamWriter, 2);
        o_displayClass->refs[0] = o_action;
        o_asyncStateMachineBox->refs[0] = o_asyncStreamWriter;
        o_asyncStateMachineBox->refs[1] = o_action;
        o_asyncStreamWriter->refs[0] = o_byteArrayOutputStream;
        o_asyncStreamWriter->refs[1] = o_asyncStateMachineBox;
        o_action->refs[i * 2] = o_displayClass;
        o_action->refs[i * 2 + 1] = o_asyncStateMachineBox;
    }

    o_runnableImplementor->refs[0] = o_action;
    o_runnableImplementor2->refs[0] = o_action;
    o_runnableImplementor3->refs[0] = o_action;

    bridge_processor->register_finalized_object(o_byteArrayOutputStream);
    bridge_processor->register_finalized_object(o_runnableImplementor);
    bridge_processor->register_finalized_object(o_runnableImplementor2);
    bridge_processor->register_finalized_object(o_runnableImplementor3);

    bridge_processor->processing_stw_step();
    bridge_processor->processing_build_callback_data(0);
    //dump_processor_state(&bridge_processor);
    assert(bridge_processor->num_sccs == 2);
    assert(bridge_processor->num_xrefs == 1);
    bridge_processor->processing_after_callback(0);
    free_callback_data(bridge_processor);
}

int main()
{
    SgenBridgeProcessor bridge_processor = { 0 };
    sgen_tarjan_bridge_init(&bridge_processor);

    test1(&bridge_processor);
    test2(&bridge_processor);

    return 0;
}
