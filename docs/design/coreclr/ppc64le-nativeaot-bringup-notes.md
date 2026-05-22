# PPC64LE NativeAOT Bring-up Notes

This note tracks the current PPC64LE NativeAOT implementation state and the
debugging workflows that are useful when changing it.

## Build And Smoke Flow

Do not build a PPC64LE host runtime for the bring-up flow. Build x64 host tools
and cross-compile the PPC64LE NativeAOT runtime pack and tests. The SDK pack
selection should use the normal local-pack switches rather than appending
`linux-ppc64le` to existing `Known*Pack` items in `eng/targetingpacks.targets`.

The baseline WSL flow is:

```sh
./build.sh clr -c Release -arch x64
./build.sh clr.tools+clr.nativeaotlibs -c Release -arch x64 /p:StripSymbols=false

ROOTFS_DIR=/ ./src/tests/build.sh -release -ppc64le -cross -nativeaot \
    -tree:nativeaot/SmokeTests \
    -log:NativeAOTSmoke \
    /p:BuildNativeAOTRuntimePack=true \
    /p:UseLocalTargetingRuntimePack=true \
    /p:UseLocalILCompilerPack=true \
    /p:UseLocalAppHostPack=true \
    /p:IsXUnitLogCheckerSupported=false \
    /p:StripSymbols=false
```

`-ppc64le` and `-cross` are both required. `-ppc64le` selects the target RID;
`-cross` sets up the native CMake cross build. Use `ROOTFS_DIR=/` for the
multi-arch/builtin-binfmt flow where the PPC64LE libraries are installed on the
WSL system instead of downloaded into a runtime rootfs.

Until the SDK knows `linux-ppc64le` as a NativeAOT-capable RID, locally patch
`.dotnet/sdk/11.0.100-preview.5.26227.104/Sdks/Microsoft.NET.Sdk/targets/Microsoft.NET.Sdk.FrameworkReferenceResolution.targets`
so `ProcessFrameworkReferences` receives `PublishAot=false` for
`RuntimeIdentifier=linux-ppc64le`:

```xml
<_ProcessFrameworkReferencesPublishAot>$(PublishAot)</_ProcessFrameworkReferencesPublishAot>
<_ProcessFrameworkReferencesPublishAot Condition="'$(RuntimeIdentifier)' == 'linux-ppc64le'">false</_ProcessFrameworkReferencesPublishAot>
...
PublishAot="$(_ProcessFrameworkReferencesPublishAot)"
```

This only bypasses the SDK's NativeAOT support gate. The test build still uses
the in-tree NativeAOT compiler, build targets, runtime pack, and local packs.
`IsXUnitLogCheckerSupported=false` avoids publishing the host-side
`XUnitLogChecker` as `linux-ppc64le`, which would require a regular CoreCLR
runtime pack that does not exist during bring-up.

The NativeAOT Unix build targets must map `linux-ppc64le` to the GNU toolchain
triple `powerpc64le-linux-gnu`. If a stale local runtime pack still generates
`--target=ppc64le-linux-gnu`, rebuild the NativeAOT runtime pack or refresh the
generated `Microsoft.NETCore.Native.Unix.targets`; otherwise Clang will not find
the cross GCC startup files and `libgcc`.

Run the rebuilt smoke scripts directly under the existing qemu-user/binfmt
setup. `DwarfDump` is currently ignored in this flow:

```sh
export CORE_ROOT=$PWD/artifacts/tests/coreclr/linux.ppc64le.Release/Tests/Core_Root
export CLRCustomTestLauncher=$PWD/src/tests/Common/scripts/nativeaottest.sh
export GLIBC_TUNABLES=glibc.rtld.optional_static_tls=128000

find artifacts/tests/coreclr/linux.ppc64le.Release/nativeaot/SmokeTests \
    -name '*.sh' ! -path '*DwarfDump*' | sort |
while IFS= read -r script; do
    bash "$script"
done
```

When the build is only compiling an individual smoke test, pass the same
`BuildNativeAOTRuntimePack` and local-pack properties through MSBuild. The local
PPC64LE pack must be built because there are no upstream PPC64LE NativeAOT
runtime packs to restore.

## Current System.Runtime Investigation

System.Runtime NativeAOT Release tests can be built through the library project
with the same local-pack switches used for smokes:

```sh
./dotnet.sh build src/libraries/System.Runtime/tests/System.Runtime.Tests/System.Runtime.Tests.csproj \
  -f net11.0-unix -c Release --no-restore \
  /p:TestNativeAot=true \
  /p:TargetArchitecture=ppc64le \
  /p:TargetOS=linux \
  /p:RuntimeFlavor=coreclr \
  /p:CrossBuild=true \
  /p:BuildNativeAOTRuntimePack=true \
  /p:UseLocalTargetingRuntimePack=true \
  /p:UseLocalILCompilerPack=true \
  /p:UseLocalCrossgen2Pack=true \
  /p:StripSymbols=false \
  /p:LibrariesConfiguration=Release
```

Run individual methods from the publish directory with the glibc static-TLS
workaround while the PPC64LE TLS model is still being hardened:

```sh
cd artifacts/bin/System.Runtime.Tests/Release/net11.0-unix/publish
GLIBC_TUNABLES=glibc.rtld.optional_static_tls=128000 \
DOTNET_PROCESSOR_COUNT=1 \
./System.Runtime.Tests -method System.Tests.SingleTests.NegativeZero
```

The NativeAOT single-file runner accepts the standard xUnit trait filters. Use
them for broad runs; unfiltered direct runs include tests that are normally
excluded by platform or active-issue traits and produce misleading failures such
as Browser-only runtime-feature tests or NativeAOT-disabled reflection tests:

```sh
cd artifacts/bin/System.Runtime.Tests/Release/net11.0-unix/publish
GLIBC_TUNABLES=glibc.rtld.optional_static_tls=128000 \
DOTNET_PROCESSOR_COUNT=1 \
./System.Runtime.Tests \
  -notrait category=nonlinuxtests \
  -notrait category=nonnetcoreapptests \
  -notrait category=IgnoreForCI \
  -notrait category=failing \
  -notrait category=OuterLoop
```

At this checkpoint, the filtered Release NativeAOT `System.Runtime.Tests` run
passes under qemu/binfmt with 68,593 tests run, 0 failures, and 122 skipped.
Focused checks for `System.Tests.SingleTests.IsSubnormal`,
`System.Text.Tests.CompositeFormatTests.MemoryExtensionsTryWrite_Valid`, and
the checked `Int128`/`UInt128` arithmetic tests pass.

One misleading clue came from disassembling a generated `DynamicInvoke` thunk
that appeared to load the argument storage from `r4` instead of the expected
fourth PPC64LE argument register `r6`. A temporary codegen probe later showed
that several dynamic-invoke thunks do map `ldarg.3` to `r6`, so do not assume
that raw symbol-name matching has found the exact thunk used by the failing
xUnit path. Use a checked PPC64LE cross-JIT and a focused `JitDump`/`JitDisasm`
before changing ABI or local-variable handling here.

Checked PPC64LE cross-JIT builds are useful for this because Release ILC does
not reliably emit JIT dumps from environment variables. Build the checked JIT
and point ILC at it with `--jitpath`; pass JIT config through repeated
`--codegenopt Name=Value` arguments. Keep temporary runtime or JIT print probes
out of commits.

Checked JIT bring-up notes from this investigation:

- PPC64LE must route INS_OPTS_RL pseudo label loads before looking up a real instruction encoding. INS_lea is a pseudo instruction used for prolog label materialization and is not present in the PPC instruction encoding table.
- Standard estimate intrinsics that lower to ordinary arithmetic still need to be marked target-supported when compiling their recursive managed bodies. PPC64LE currently expands Abs, Sqrt, MultiplyAddEstimate, ReciprocalEstimate, and ReciprocalSqrtEstimate in the JIT.
- PPC DS-form load/store instructions have stricter displacement requirements than signed-16 range. Stack struct-copy code must allocate address temporaries when std/ld offsets are unaligned even if the offset numerically fits.
- PPC FP/int register-class moves used for ABI shuffles are bit-preserving moves; use mffprd/mtfprd for 8-byte transfers instead of treating them as regular integer or FP register copies.

Split-parameter frame-layout investigation notes:

- The failing xUnit theory made `InvokeTestAsync` iterate a
  `NativeReader` object as if it were the constructor-argument `object[]`.
  A live debugger run showed `AfterTestCaseStartingAsync` loaded the correct
  array into callee-saved `r22`, then `r22` became the `NativeReader` after the
  call path through `GetBeforeAfterTestAttributes`.
- The first bad callee was
  `System.Reflection.Runtime.General.MetadataReaderExtensions.CreateRuntimeAssemblyNameFromMetadata`.
  Its broken prolog saved `r22` at `400(r1)`. Since the method established
  `r31 = r1 + 320`, that save slot was also `80(r31)`. The method then
  reassembled a split argument with `std r10,80(r31)`, overwriting the saved
  `r22` with the `NativeReader`.
- PPC64LE split parameters are now treated like RISC-V and LoongArch: do not
  promote split multireg struct parameters, and do not apply the fixed
  save-area delta when finalizing their local stack homes. Their virtual
  offsets are already frame-pointer-relative local homes. Applying the extra
  delta moves them into the callee-saved save area.
- The fixed image still saves `r22` at `400(r1)`, but the split argument homes
  in `CreateRuntimeAssemblyNameFromMetadata` are at negative FP-relative
  offsets such as `-128(r31)` and `-120(r31)`, so they no longer overlap the
  callee-saved register save slots.

## PPC64LE ABI Entry Points And Thunks

PPC64LE ELFv2 uses `r2` as the TOC pointer. Cross-module calls enter global
entry points with `r12` holding the callee entry address, allowing the callee to
derive its own TOC. Calls that may cross TOC domains must assume `r2` can be
clobbered and restore the caller TOC after returning.

`[UnmanagedCallersOnly(EntryPoint = ...)]` exports point directly at the
managed method body. The JIT emits the PPC64LE global-entry TOC setup in the
method prolog, and the ELF writer annotates matching symbols with localentry 16
so same-module calls can skip that setup while external callers enter through
the global entry.

P/Invoke calls use an outbound managed-to-native sequence in the JIT. Direct
targets are loaded through the GOT into `r12`, called through CTR, and followed
by an `r2` restore. Indirect unmanaged calls use the same convention after
moving the target address into `r12`. This keeps linker-inserted PLT entries out
of managed-generated call sites.

Extern symbols used by the JIT helper path are emitted as normal extern
function symbols. Runtime helpers are expected to be in the current module; if a
helper maps to a true external dependency, the call site needs an explicit
ABI-correct sequence instead of a generated text-section thunk.

PPC64LE math `[RuntimeImport]` entries resolve to local `RhpPpc64leMath*`
runtime wrappers. The wrappers live in `MathHelpers.cpp` and make the external
libm calls from native runtime code, keeping the managed call sites in-module.
JIT floating-point remainder helpers use the same wrappers for `fmod`/`fmodf`
because `%` on `float`/`double` is emitted through helper calls rather than the
CoreLib `RuntimeImport` declarations.

PPC64LE memory helpers that would otherwise bind to libc `memmove`/`memset`
resolve to local `RhpPpc64leMem*` runtime wrappers in `MiscHelpers.cpp`. This
keeps managed and JIT-helper call sites in-module while leaving the native
runtime object code responsible for any external libc call sequence.

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
4. Map the suspicious IP to a method with `powerpc64le-linux-gnu-nm -an`,
   `powerpc64le-linux-gnu-objdump -d`, or the NativeAOT code manager ranges.
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

Useful repro variants:

```sh
DOTNET_GCStress=0xC \
DOTNET_StressLog=1 \
DOTNET_TotalStressLogSize=67108864 \
DOTNET_StressLogLevel=9 \
./artifacts/tests/coreclr/linux.ppc64le.Release/nativeaot/SmokeTests/DynamicGenerics/DynamicGenerics/native/DynamicGenerics \
    ThreadLocalStatics.TLSTesting.ThreadLocalStatics_Test

DOTNET_PROCESSOR_COUNT=1 \
DOTNET_GCStress=0xC \
DOTNET_StressLog=1 \
DOTNET_TotalStressLogSize=67108864 \
DOTNET_StressLogLevel=9 \
<same command>

DOTNET_gcConservative=1 \
DOTNET_GCStress=0xC \
DOTNET_StressLog=1 \
DOTNET_TotalStressLogSize=67108864 \
DOTNET_StressLogLevel=9 \
<same command>
```

`DOTNET_PROCESSOR_COUNT=1` is only a noise reducer. If the failure remains, do
not label it a concurrency issue. `DOTNET_gcConservative=1` is the stronger
split: if conservative reporting fixes the repro, look at precise stack GC
info; if it does not, inspect hijacking, transition frames, statics/TLS, helper
ABIs, and unmanaged boundaries.

Capturing the stress log through a debugger can be fragile under qemu-user, so
prefer raw chunk dumps over interactive formatted output. The raw files can be
decoded repeatedly while changing the analysis script, and they keep evidence
stable even if qemu, GDB, or LLDB lose the original process state. SIG34 is used
by NativeAOT thread hijacking during stop-the-world and is usually noise.

The checked-in debugger capture helpers dump `StressLog::theLog` metadata and
all reachable `StressLogChunk` instances to a directory. The decoder reconstructs
the readable log by resolving format strings from the NativeAOT ELF image:

```sh
python3 src/tools/StressLogAnalyzer/scripts/decode_nativeaot_stresslog.py \
    /tmp/stresslog-capture \
    --module ./artifacts/tests/coreclr/linux.ppc64le.Release/nativeaot/SmokeTests/DynamicGenerics/DynamicGenerics/native/DynamicGenerics \
    --output /tmp/stresslog.txt
```

GDB capture from a stopped process or core:

```text
(gdb) set pagination off
(gdb) handle SIG34 nostop noprint pass
(gdb) source src/tools/StressLogAnalyzer/scripts/dump_nativeaot_stresslog_gdb.py
(gdb) dump_nativeaot_stresslog /tmp/stresslog-capture
```

For qemu-user with a GDB stub, start the test with a debug port and attach:

```sh
qemu-ppc64le -g 1234 ./DynamicGenerics ThreadLocalStatics.TLSTesting.ThreadLocalStatics_Test
gdb-multiarch ./DynamicGenerics
```

```text
(gdb) target remote :1234
(gdb) handle SIG34 nostop noprint pass
(gdb) continue
```

LLDB capture from a stopped process or core:

```text
(lldb) process handle -p true -n false -s false SIG34
(lldb) command script import src/tools/StressLogAnalyzer/scripts/dump_nativeaot_stresslog_lldb.py
(lldb) dump_nativeaot_stresslog /tmp/stresslog-capture
```

When helper scripts cannot resolve debug type names automatically, the manual
fallback is to inspect `StressLog::theLog` and dump each chunk:

- `info variables StressLog`, `info variables theLog`, or LLDB `image lookup -rn
  StressLog` to find the globals.
- `ptype StressLog`, `ptype ThreadStressLog`, and `ptype StressLogChunk`, or
  LLDB `image lookup -type StressLog`, to confirm the layout used by the binary.
- GDB `dump binary memory <file> <start> <end>` or LLDB
  `memory read --binary --outfile <file> <start> <end>` for each chunk.

For qemu-user native crashes, enable core dumps before running the repro:

```sh
ulimit -c unlimited
```

Recent qemu-user builds commonly write files named like
`qemu_<guest-exe>_<YYYYMMDD-HHMMSS>_<qemu-pid>.core`. These cores are often more
reliable than live debugger sessions for SIGSEGV/SIGABRT triage. Still, SIG34
stops are usually hijacking noise, not the failing condition.

Core dumps are most useful when every run writes into its own directory with the
command line and environment saved beside the core. For qemu-user NativeAOT
smokes, save at least:

- The executable and any `.so` files from the test's `native` directory.
- The exact runtime libraries used by the multi-arch system or sysroot.
- The main binary with `StripSymbols=false`, or the matching `.dbg` files.
- `llvm-readelf -n <core>` output, so the core flavor and captured notes are
  visible even if a later debugger cannot load it.
- `llvm-nm -an <binary>` output for quick IP-to-symbol lookup.

When a core contains a bad object reference, first identify whether the bad
value is an object pointer, an interior pointer, a stack address, a code
address, or a fill pattern such as `0xcdcdcdcdcdcdcdcd`. Fill patterns usually
mean an uninitialized local or a poisoned debug allocation reached a reporting
path; they are not automatically proof that the GC moved an object incorrectly.

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

Do not patch GC info based on one suspicious method name alone. Previous
investigations produced plausible methods such as
`Interop.Sys.GetLowResolutionTimestamp` and `Environment.TickCount64`, but the
right question is always more concrete: at the stopped IP, which exact stack
slots and registers did the runtime report, which references were live in the
JIT dump, and which of those locations later contained the corrupted value?

Good artifacts to keep for a GC-hole bug report:

- A minimized command that fails within a few runs.
- The binary, symbols, and `llvm-nm -an` output.
- The last several GC stress-log chunks, preferably raw plus decoded text.
- The top managed frames and stopped IPs for each thread in the last GC.
- JIT dumps for methods on those top frames, with `JitGCDump=1`.
- A short table of suspect stack slots: address, frame, method, variable or
  temp name, GC type, and whether it was tracked or untracked.

For NativeAOT JIT dumps from an ILC build, pass focused codegen options rather
than dumping the whole image:

```text
--codegenopt "JitDump=<method-pattern>" --codegenopt JitGCDump=1
```

When using the test build scripts, keep `-p:StripSymbols=false` in the MSBuild
arguments and record any non-default `IlcExtraArgs`, linker, sysroot, or
runtime-pack overrides. Stale ILC layouts can make an investigation look
impossible; verify the `ilc` executable or wrapper being used by the test tree
matches the compiler binaries just rebuilt.

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

Frame-related PPC64LE invariants worth checking after every prolog/epilog
change:

- SP must always point at the active linkage area whenever unmanaged ABI code
  can observe the frame.
- Saved LR, saved `r2`, callee-saved registers, outgoing argument space, and
  local slots must agree between codegen, unwind info, and the NativeAOT code
  manager.
- If a large frame forces split SP adjustment, all callee-save offsets must
  still be encodable at the instruction that saves or restores them.
- Epilog recognition must cover both normal methods and funclets. A missing
  epilog shape can make hijacking overwrite or read the return address from the
  wrong frame.
- A debug-only frame-shape workaround should not survive cleanup unless it is
  described as an ABI requirement.

`[UnmanagedCallersOnly]` methods are reverse P/Invoke methods. They get the JIT
reverse-P/Invoke enter/exit helpers and must be entered using the unmanaged ABI.
For PPC64LE ELFv2, that means unmanaged callers arrive with `r12` containing the
entry address. The method prolog can use this to establish the NativeAOT TOC in
`r2` before any TOC-relative access. This avoids a separate export thunk and
matches the intended external-entry shape for these methods.

NativeAOT can still make same-module native calls to `[UnmanagedCallersOnly]`
entrypoints such as startup helpers. PPC64 ELFv2 handles this with dual entry
points: external callers enter at the symbol value, while local calls branch to
`symbol+localentry` and preserve the current TOC. The PPC64LE UCO prolog uses
`addis/addi/subf/nop` to establish `r2`; the `nop` pads the global entry to a
16-byte local entry offset. In `st_other`, localentry 16 is encoded as
`4 << STO_PPC64_LOCAL_BIT` (`0x80`), not as the byte count itself. The ELF
writer applies this based on the compiled method body being
`IsUnmanagedCallersOnly`; it does not need to pattern-match the prolog bytes
because the JIT interface always sets `CORJIT_FLAG_REVERSE_PINVOKE` for these
methods, and the PPC64LE prolog hook emits the global-entry sequence for every
reverse P/Invoke body.

Unmanaged calls use the PPC64LE global-entry convention: save managed `r2`, put
the target address in `r12`, branch through CTR, then restore `r2`. Direct
P/Invoke calls load the target from the GOT; indirect unmanaged calls move the
already-computed target into `r12`.

CoreCLR JIT code currently uses absolute address materialization for method
body references when `compReloc` is false; it does not rely on `r2` as a JIT
TOC pointer. In that shape, reverse-P/Invoke / `[UnmanagedCallersOnly]` methods
do not need a synthetic global-entry TOC prefix, and managed direct-call targets
must not be adjusted by a local-entry offset. Keep the ELFv2 dual-entry
`symbol+localentry` rule for relocatable R2R/AOT code shapes that actually use
TOC-relative addressing. If CoreCLR JIT ever starts using TOC-relative data
references, add an explicit JIT-side local-entry convention at the same time as
the TOC-establishing prefix so direct same-code-heap calls skip the prefix and
external/UCO function-pointer callers enter with `r12` set to the global entry.
Even without a JIT TOC, indirect calls should still branch through `r12`.
Managed targets do not depend on this, but runtime helpers and other native
global entries do; branching through an arbitrary register can enter a PPC64
ELFv2 global entry with stale `r12`, leading to a bogus callee TOC before the
first TOC-relative load or PLT call.

CoreCLR PPC64LE stublinker code follows the same rule for computed
instantiating method stubs: shuffle GPR arguments, materialize the hidden
instantiation argument, adjust boxed `this` for unboxing stubs, and tailcall the
target through `r12`. This is required for generic delegate/reflection paths
used by the libraries xUnit runner.

Small call descriptors store the live callee-saved GC register mask in
`idReg1`/`idReg2`, not just physical register numbers. PPC64LE has 17 integer
callee-saved registers (`r14`-`r30`), so `REGNUM_BITS` is sized to 9 and the PPC
`instrDesc` layout puts those fields before `_idGCref` to avoid bitfield padding
at the 32-bit storage-unit boundary. Keep this paired with
`emitEncodeCallGCregs`/`emitDecodeCallGCregs`; do not paper over encoding gaps
by forcing every call with a live GC register into the large descriptor path.

No-GC regions and GC reporting must be audited together. Helper calls marked as
no-GC can still trash volatile registers; the kill set must match the assembly
helper ABI. For write barriers and assignment helpers, labels ending in
`AVLocation` must remain immediately attached to the dereferencing instruction
used for null-reference fault recognition. Do not insert barriers or probes
between an `AVLocation` label and the faulting access.

No-GC decisions that are easy to get wrong:

- A no-GC helper call is not a no-clobber call. Volatile registers holding GC
  refs must be dead, spilled to reported locations, or preserved by a documented
  helper-specific ABI.
- If codegen disables GC around a helper transition, the transition point still
  needs accurate state on both sides. Check the instruction immediately before
  `GT_START_NONGC` and immediately after `GT_START_PREEMPTGC`.
- Assignment helpers and write barriers often rely on exact register contracts.
  PPC64LE helper assembly should state which argument, scratch, return, and
  thread registers it uses, and JIT lowering should match that contract.
- Do not infer that a helper is safe to call from a hijack or probe path just
  because it is no-GC. Hijack paths also have return-value and stack-layout
  preservation constraints.

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

Struct-return and copy checklist:

- Confirm the ABI classification first: integer registers, floating registers,
  mixed aggregate, vector, or hidden return buffer.
- Compare the PPC64LE path with ARM64 and x64 before adding a PPC-only local
  bounce. The generic multi-reg return machinery is usually the right owner.
- If a return buffer is used, verify the hidden argument is not confused with
  the normal first user argument and that reverse P/Invoke/PInvoke transitions
  preserve it.
- If a struct contains GC references, every intermediate location used by a copy
  must either be non-GC by construction or be reported for the full live range.
- Large-offset address materialization should be solved in address lowering or
  frame layout, not hidden inside return-copy code unless the ABI specifically
  requires it.

## Current JIT Gaps

The PPC64LE JIT backend still has several known incomplete areas. Keep this
list current as the bring-up matures:

- Atomic IR support is present for pointer-sized and 32-bit `Interlocked.*`
  operations that lower to `GT_CMPXCHG`, `GT_XADD`, `GT_XCHG`, `GT_XAND`, and
  `GT_XORR`. The PPC64LE backend uses conservative `sync` barriers around
  `lwarx`/`ldarx` plus `stwcx.`/`stdcx.` reservation loops. Byte and short
  overloads still fall back to helpers.
- OSR root frames need PPC64LE-specific handling in
  `genOSRHandleTier0CalleeSavedRegistersAndFrame`, or OSR should remain
  explicitly blocked.
- Varargs are not implemented in the PPC64LE ABI classifier and
  `genJmpPlaceVarArgs`.
- Fast tail calls are disabled. Codegen still has defensive NYI paths for fast
  tail call stack argument placement and call emission.
- SIMD/VSX and hardware intrinsics are not implemented. `FEATURE_SIMD` is
  intentionally blocked for PPC64LE.
- PPC64LE `genCodeForTreeNode` does not implement the RISC-V-specific Zba/Zbs
  fused ops (`GT_SH*ADD*`, `GT_ADD_UW`, `GT_SLLI_UW`, `GT_BIT_*`) because the
  PPC64LE lowerer does not introduce those IR nodes. It also lacks general
  `GT_INTRINSIC`, `GT_CKFINITE`, `GT_SWAP`, and patchpoint handling; add these
  when the corresponding importer/lowerer paths are enabled for PPC64LE.
- `GT_FIELD_LIST` should remain contained by lowering. If it reaches codegen,
  treat it as a lowering bug rather than adding real code emission.
- Floating-point callee-saved registers F14-F31 are not available to LSRA until
  prolog/epilog save and restore support is implemented.
- Large stack-frame and large local-offset cases still have NYI paths. Prefer
  fixing address lowering, LSRA temporary allocation, or frame layout instead
  of hiding special cases in individual codegen sites.
- PPC64LE lowering is intentionally conservative: many containment hooks are
  empty, target intrinsics return false, and optimized write barriers are not
  emitted. These are mostly code quality gaps once correctness is stable.

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

When an address sequence needs PPC64 relocations, prefer a human-readable
assembler-shaped sequence in comments and one logical relocation in the JIT or
object writer. The native file may expand that logical relocation into `_HA`
and `_LO` records, but the importer, JIT, and dependency node should not pass
around unrelated integer addends that only make sense for one half of the pair.

When debugging generated code, build tests with `StripSymbols=false` so symbols
stay in the primary binary instead of separate `.dbg` files. NativeAOT smoke
tests commonly report success with exit code `100`; do not treat exit code `0`
as the only successful result.

Prefer `powerpc64le-linux-gnu-objdump` over `llvm-objdump` for PPC64LE
disassembly during bring-up. `llvm-objdump` has repeatedly timed out on the
large NativeAOT shared libraries and executables, while GNU objdump has produced
the targeted section/address disassembly immediately. Use `-j __managedcode`
when inspecting managed method bodies.
