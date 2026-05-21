# PPC64LE NativeAOT Bring-up Notes

This note tracks PPC64LE NativeAOT bring-up decisions that are easy to lose in
local debugging history.

## PPC64LE ABI Thunk Nodes

PPC64LE ELFv2 uses `r2` as the TOC pointer. Cross-module calls enter global
entry points with `r12` holding the callee entry address, allowing the callee to
derive its own TOC. Calls that may cross TOC domains must assume `r2` can be
clobbered and restore the caller TOC after returning.

`Ppc64leUnmanagedCallersOnlyExportThunkNode` was originally used for inbound
native-to-managed exports. It generated a PPC64LE global-entry-like shim for
`[UnmanagedCallersOnly(EntryPoint = ...)]` methods, established the NativeAOT
image TOC, and tail-jumped into the managed method body. The better long-term
shape is to make the JITted method body itself use a PPC64LE global-entry
prolog when compiling an `UnmanagedCallersOnly` method, since these methods are
expected to be entered from unmanaged code.

`Ppc64leExternFunctionThunkNode` is an outbound managed-to-native shim for
external helper symbols used by the JIT. It saves LR and the managed TOC,
calls the real external function through the GOT, restores `r2`, restores LR,
and returns. This lets managed code call a local thunk while the thunk performs
the ELFv2 call ceremony.

`Ppc64leRuntimeImportMethodNode` is the same outbound ABI shim shape, but used
as the method entrypoint for selected `[RuntimeImport]` methods such as math
and memory helpers. Its hardcoded import-symbol allowlist is a bring-up
artifact. The preferred structural fix is to teach PPC64LE direct unmanaged
calls in the JIT/object writer to load the external function address through the
GOT into `r12`, branch through CTR, and restore `r2` at each call site. That
should remove the need for these outbound thunk nodes for managed-generated
calls and avoid linker-inserted PLT entries in managed code.

## GC Hole Debugging

For flaky NativeAOT failures under `DOTNET_GCStress=0xC`, treat GC corruption
as the default hypothesis until proven otherwise. Reduced concurrency is a
useful sanity check, but `DOTNET_PROCESSOR_COUNT=1` passing or failing is not a
root-cause signal by itself. QEMU user-mode execution also does not model all
real PPC hardware ordering behavior, so avoid overfitting failures to partial
load/store theories without evidence.

The recurring workflow is:

1. Minimize the repro command and preserve the exact binary, symbols, sysroot,
   environment, and command line.
2. Enable stress logging with a large buffer. A useful starting point is
   `DOTNET_StressLog=1 DOTNET_TotalStressLogSize=67108864 DOTNET_StressLogLevel=9`.
3. Capture the stress log, find the object or stack location that was corrupted
   or overwritten, then walk backward in the log to the frame/static/TLS report
   that last described it.
4. Map the suspicious IP to a method with `llvm-nm -n`, `llvm-objdump -d`, or
   the NativeAOT code manager ranges.
5. Generate a focused JIT dump with
   `--codegenopt "JitDump=<method-pattern>" --codegenopt JitGCDump=1`, then
   compare the reported stack slots, interruptible regions, and no-GC windows
   against the disassembly.

The stress log is most useful when it is treated as a timeline. Start near the
failure and identify the overwritten reference, stack address, or suspicious
object. Then walk backward through the last few GCs and record:

- Which threads were stopped and at what managed IPs.
- Whether each IP was in an interruptible region, call site, prolog, or epilog.
- Which stack slots, callee-saved registers, statics, or TLS locations were
  reported for the frame.
- Whether the same address was later reused for a different stack frame.

If the log points to a stack root, inspect the method's GC info before changing
runtime stack walking. A typical PPC64LE failure mode is an address being
reported correctly at one safe point but omitted at a neighboring interruptible
point, or a slot being described relative to SP when the method's prolog/epilog
and the code manager disagree about the current frame shape.

Capturing the stress log through a debugger can be fragile under qemu-user.
GDB and LLDB may stop on SIG34, which NativeAOT uses for thread hijacking during
stop-the-world. In LLDB, issue this as early as possible:

```text
process handle -p true -n false -s false SIG34
```

If debugger capture is unreliable, temporarily adding an in-process stress-log
dumper is acceptable for narrowing a bug, but keep that code out of cleanup
commits. A reusable GDB capture script is preferable: dump the in-memory
`StressLog::theLog` chunks to files, then decode the binary chunks offline using
the structure layout in `stresslog.h` or `stressLog.h` that matches the binary.
The format pointer in a stress-log record is an offset from the module base
recorded in the log.

When debugger capture does work, prefer dumping the raw chunks over relying on
interactive formatted output. The raw files can be decoded repeatedly while
changing the analysis script, and they keep evidence stable even if qemu, GDB,
or LLDB lose the original process state. Useful debugger probes are:

- `info variables StressLog` and `info variables theLog` to find the globals.
- `ptype StressLog`, `ptype ThreadStressLog`, and `ptype StressLogChunk` to
  confirm the layout used by the binary being debugged.
- `dump binary memory <file> <start> <end>` for each chunk when helper scripts
  cannot resolve debug type names automatically.

For qemu-user native crashes, enable core dumps before running the repro:

```sh
ulimit -c unlimited
```

Recent qemu-user builds commonly write files named like
`qemu_<guest-exe>_<YYYYMMDD-HHMMSS>_<qemu-pid>.core`. These cores are often more
reliable than live debugger sessions for SIGSEGV/SIGABRT triage. Still, SIG34
stops are usually hijacking noise, not the failing condition.

Use `DOTNET_gcConservative=1` to separate precise GC reporting holes from other
state corruption. If conservative GC makes the failure disappear, inspect stack
root reporting. If it still fails, look harder at hijacking, transition frames,
statics/TLS reporting, register preservation, and unmanaged helper paths.

Two quick experiments narrow the surface without proving the root cause:

- `DOTNET_PROCESSOR_COUNT=1` reduces scheduling variability, but a remaining
  failure is still compatible with GC reporting or hijacking bugs.
- Temporarily making `RhpGcProbeHijack` return after the trap-flag check splits
  ordinary return-address hijacking from probe-frame construction. If the
  failure disappears, inspect the slow path and probe frame GC info. If it
  remains, inspect hijack offset calculation, epilog recognition, and DWARF CFI.

For stack overflow or runaway recursion under stress, always capture a stack
trace. Look for repeated class constructors, helper paths that should not
re-enter managed code, and frames whose SP changes unexpectedly across a
stop-the-world hijack. PPC64LE hijacking bugs can masquerade as recursion if the
restored return address or saved SP is taken from the wrong stack slot.

## PPC64LE JIT Decisions

Frame layout follows the PPC64 ELFv2 linkage convention closely. The caller's
linkage area remains at the top of the stack, and the JIT reserves fixed slots
used by ABI-sensitive paths, including the TOC save slot at offset 24 from SP
for unmanaged calls that can clobber `r2`. Keep this offset in sync with any
changes to call lowering or frame allocation.

The local frame size intentionally includes the outgoing argument area and the
PPC64 linkage/parameter-save area. This keeps locals and spill temps above the
caller-owned call area so a helper call made while preparing another call cannot
overwrite values that are still live. Large local frames may be split into an
initial SP adjustment, register saves, and a deferred SP adjustment so save
offsets remain encodable and unwindable.

The normal prolog may split frame allocation into an initial allocation and a
deferred allocation so callee-saved register saves stay within encodable
offsets and within the unwind encoding limits. When changing prolog/epilog
shape, re-check `TrailingEpilogueInstructionsCount`, hijack offset calculation,
DWARF CFI, and the NativeAOT `UnixNativeCodeManager` epilog recognizer.

Return-address hijacking depends on exact frame facts. For PPC64LE, check the
generated epilog sequences from both `genFnEpilog` and `genFuncletEpilog`
against `TrailingEpilogueInstructionsCount`. The code manager needs to know
whether the current IP is before LR restore, after LR restore but before SP
restore, or after SP restore, because the return address location moves between
the current frame and the caller linkage area.

`[UnmanagedCallersOnly]` methods are reverse P/Invoke methods. They get the JIT
reverse-P/Invoke enter/exit helpers and must be entered using the unmanaged ABI.
For PPC64LE ELFv2, that means unmanaged callers arrive with `r12` containing the
entry address. The method prolog can use this to establish the NativeAOT TOC in
`r2` before any TOC-relative access. This avoids a separate export thunk and
matches the intended external-entry shape for these methods.

Indirect unmanaged calls already use the PPC64LE global-entry convention:
save managed `r2`, move the target address into `r12`, branch through CTR, then
restore `r2`. Direct unmanaged calls should eventually use the same structural
shape with a GOT-loaded target in `r12` instead of relying on per-symbol thunk
nodes or linker-inserted PLT entries in managed code.

No-GC regions and GC reporting must be audited together. Helper calls marked as
no-GC can still trash volatile registers; the kill set must match the assembly
helper ABI. For write barriers and assignment helpers, labels ending in
`AVLocation` must remain immediately attached to the dereferencing instruction
used for null-reference fault recognition. Do not insert barriers or probes
between an `AVLocation` label and the faulting access.

`GT_START_NONGC`/`GT_START_PREEMPTGC`, helper kill sets, and call-site GC labels
are not independent details. A register or stack slot that contains a GC
reference across a no-GC helper must either be preserved by that helper ABI or
be reported/killed consistently before and after the helper. When debugging a
hole, compare the JIT dump's live GC sets with the disassembly around:

- Stores of `GCT_GCREF` and `GCT_BYREF` locals.
- Helper calls that the JIT believes are no-GC.
- `genDefineTempLabel` points used to force a GC-info boundary.
- The last instruction before disabling GC and the first instruction after
  enabling it again.

Struct returns are easy to break on PPC64LE because the ABI uses multiple
integer/floating return registers for small aggregates, while larger or
non-enregisterable structs use return buffers. `VarTypeIsMultiByteAndCanEnreg`
must reflect the PPC64LE ABI; otherwise the JIT may invent PPC-specific local
copy/load workarounds that fight the wrong classification. Keep return-register
copying close to the cross-architecture pattern unless the ABI requires a clear
exception.

For multi-register returns, prefer moving directly from the ABI return registers
reported by `ReturnTypeDesc::GetABIReturnReg` into the registers allocated for
the call node. Avoid PPC-only "load return from local" sequences unless there is
a concrete ABI reason. If the return value has to be materialized through a
local, verify that the local is typed and reported correctly and that the copy
does not introduce a GC hole between the call and the final destination.

Struct copies should follow the existing JIT decomposition rules. If a PPC64LE
change needs a special temporary register for a large stack offset, first check
whether the type classification or address-mode lowering is wrong. Several
early workarounds around struct returns and large local offsets turned out to be
symptoms of incorrect enregistration decisions rather than real PPC ABI needs.

`RhpGcProbeHijack` is entered by overwriting a return address during thread
hijacking. It must preserve any valid return values and avoid clobbering
registers or stack locations that may hold the interrupted method's return
state. Keep the fast path minimal: check the trap flag, restore hijacked state
through the same `FixupHijackedCallstack` pattern used by other platforms, and
avoid calls unless the slow path has intentionally built the correct probe
frame.

The PPC64LE hijack path should be reviewed against ARM64 when in doubt. The
entry can only use volatile scratch registers until it has decided to build a
probe frame, and it must not touch stack locations that may contain a return
buffer, saved return value, or caller linkage data. If the trap flag is clear,
the path should restore the original return address and return with the
interrupted method's return values intact.

For TLS, prefer inline TLS access sequences in assembly and JIT-generated code
over helper calls when the generated code can match the shared-library-safe
model. PPC64LE shared-library tests are sensitive to static TLS exhaustion; the
test environment may need
`GLIBC_TUNABLES=glibc.rtld.optional_static_tls=128000`, but this is a runtime
loader workaround, not a substitute for correct TLS code shape.

Relocation pairs should be represented as compound relocation types at the JIT
and object-writer boundary when the pair is logically one address materialization
operation. PPC64LE HA/LO pairs should follow the same style as ARM and RISC-V
compound relocations instead of threading ad hoc addends through generic
relocation records.

When debugging generated code, build tests with `StripSymbols=false` so symbols
stay in the primary binary instead of separate `.dbg` files. NativeAOT smoke
tests commonly report success with exit code `100`; do not treat exit code `0`
as the only successful result.
