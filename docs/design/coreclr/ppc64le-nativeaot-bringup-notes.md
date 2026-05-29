# PPC64LE CoreCLR And NativeAOT Bring-up Notes

This note is a practical guide for the PPC64LE port. Keep it focused on how to
build, test, debug known classes of failures, and understand current design
decisions and open gaps. Resolved investigations belong in commit history, not
here.

## Workspace

The active checkout lives directly inside WSL:

```sh
cd /home/filip/runtime-ppc64le-wsl
```

Do not maintain a second synchronized checkout and do not prefix local commands
with `wsl`; run build, test, debugger, and qemu/binfmt commands directly from
this tree.

Use `ROOTFS_DIR=/` for the current multi-arch/builtin-binfmt setup where the
PPC64LE libraries are installed on the WSL system instead of downloaded into a
separate rootfs.

## CoreCLR Build Flow

Checked builds are preferred while bring-up issues are active because JIT and
runtime assertions catch many ABI and GC-info mistakes before they turn into
silent corruption.

```sh
ROOTFS_DIR=/ ./build.sh clr.runtime -rc Checked -lc Debug -arch ppc64le -cross --build
```

Generate or refresh the Core_Root layout when test binaries or runtime bits are
stale:

```sh
ROOTFS_DIR=/ ./src/tests/build.sh ppc64le Checked -generatelayoutonly
```

The checked Core_Root normally lives at:

```sh
artifacts/tests/coreclr/linux.ppc64le.Checked/Tests/Core_Root
```

## CoreCLR Test Flow

For first-pass CoreCLR JIT debugging, keep ReadyToRun disabled and start with
tiered compilation disabled:

```sh
export CORE_ROOT=$PWD/artifacts/tests/coreclr/linux.ppc64le.Checked/Tests/Core_Root
export DOTNET_ReadyToRun=0
export DOTNET_TieredCompilation=0
export DOTNET_EnableWriteXorExecute=0
```

`DOTNET_EnableWriteXorExecute=0` avoids a qemu/binfmt SIGILL mode seen in
dynamic reflection invoke stubs. Re-enable it only when specifically testing
W^X behavior.

Run CodeGenBringUpTests:

```sh
for t in d r ro; do
    CORE_ROOT=$PWD/artifacts/tests/coreclr/linux.ppc64le.Checked/Tests/Core_Root \
    DOTNET_ReadyToRun=0 \
    DOTNET_TieredCompilation=0 \
    DOTNET_EnableWriteXorExecute=0 \
    artifacts/tests/coreclr/linux.ppc64le.Checked/JIT/CodeGenBringUpTests/JIT.CodeGenBringUpTests_$t/JIT.CodeGenBringUpTests_$t.sh
done
```

Run the OSR test set with tiering enabled. Low counters are useful when
validating patchpoint transition mechanics:

```sh
find artifacts/tests/coreclr/linux.ppc64le.Checked/JIT/opt/OSR -name '*.sh' | sort |
while read t; do
    CORE_ROOT=$PWD/artifacts/tests/coreclr/linux.ppc64le.Checked/Tests/Core_Root \
    DOTNET_ReadyToRun=0 \
    DOTNET_EnableWriteXorExecute=0 \
    DOTNET_TC_OnStackReplacement_InitialCounter=1 \
    DOTNET_OSR_HitLimit=2 \
    "$t"
done
```

Skip tests that depend on launching `ilasm`/`ildasm` inside the emulated
PPC64LE CoreCLR process for now. That path is not a useful runtime signal in
the current qemu-user setup.

For broad `System.Runtime.Tests` CoreCLR runs under qemu/binfmt, disable
RemoteExecutor tests unless the process-launch behavior is the thing being
tested:

```sh
export DOTNET_REMOTEEXECUTOR_SUPPORTED=0
```

RemoteExecutor failures that report `ENOENT` for an existing PPC64LE executable
are usually qemu/binfmt process-launch issues, not CoreCLR codegen failures.

## NativeAOT Build Flow

Do not build a PPC64LE host runtime for the bring-up flow. Build x64 host tools
and cross-compile the PPC64LE NativeAOT runtime pack and tests.

```sh
./build.sh clr -c Release -arch x64
./build.sh clr.tools+clr.nativeaotlibs -c Release -arch x64 /p:StripSymbols=false
./build.sh clr.alljitscommunity -c Release -arch x64 --build /p:StripSymbols=false

ROOTFS_DIR=/ ./build.sh clr.nativeaotruntime -c Release -arch ppc64le -cross --build /p:StripSymbols=false
ROOTFS_DIR=/ ./build.sh clr.nativeaotlibs -c Release -arch ppc64le -cross --build /p:StripSymbols=false
```

After rebuilding host tools, make sure the PPC64LE ILC layout has a matched
x64-hosted PPC64LE JIT and `libjitinterface_x64.so`:

```sh
cp -p artifacts/bin/coreclr/linux.x64.Release/libclrjit_unix_ppc64le_x64.so* \
    artifacts/bin/coreclr/linux.ppc64le.Release/x64/ilc/
cp -p artifacts/bin/coreclr/linux.x64.Release/libjitinterface_x64.so \
    artifacts/bin/coreclr/linux.ppc64le.Release/x64/ilc/
cp -p artifacts/bin/coreclr/linux.x64.Release/libjitinterface_x64.so \
    artifacts/bin/coreclr/linux.ppc64le.Release/x64/crossgen2/
```

Stale copies can look like real JIT or NativeAOT failures. A checked JIT may
return `CodeGenerationFailed` before entering the JIT due to a JIT-interface
GUID mismatch; release ILC can trip stack-smash checks in the shim.

Build NativeAOT smoke tests:

```sh
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

`-ppc64le` selects the target RID. `-cross` selects the native CMake cross
build. The SDK pack selection should use normal local-pack switches rather than
adding `linux-ppc64le` to existing `Known*Pack` items in
`eng/targetingpacks.targets`.

Until the SDK knows `linux-ppc64le` as a NativeAOT-capable RID, local SDK
patches may be needed so `ProcessFrameworkReferences` receives
`PublishAot=false` for `RuntimeIdentifier=linux-ppc64le`. This only bypasses
the SDK support gate; the tests must still use the in-tree NativeAOT compiler,
targets, runtime pack, and local packs.

The NativeAOT Unix build targets must map `linux-ppc64le` to
`powerpc64le-linux-gnu`. If generated targets use `--target=ppc64le-linux-gnu`,
refresh the local runtime pack; Clang will otherwise miss the cross GCC startup
files and `libgcc`.

Run smoke scripts directly under qemu-user/binfmt. `DwarfDump` can be skipped
when the goal is managed runtime validation:

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

When building a single NativeAOT test through MSBuild, pass the same local-pack
properties used for smokes. There are no upstream PPC64LE NativeAOT runtime
packs to restore during bring-up.

## System.Runtime.Tests NativeAOT Flow

Build NativeAOT `System.Runtime.Tests` through the library project:

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

Run from the publish directory:

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

The NativeAOT single-file runner accepts standard xUnit trait filters. Avoid
unfiltered direct runs for broad signal because they include tests normally
excluded by platform or active-issue traits.

Use the glibc static TLS tunable while the PPC64LE TLS model is still being
hardened:

```sh
export GLIBC_TUNABLES=glibc.rtld.optional_static_tls=128000
```

This is a runtime loader workaround, not a substitute for correct generated TLS
access sequences.

## Current Runtime Configuration Gates

These defaults and guards are intentional during bring-up:

- OSR and `TC_QuickJitForLoops` use the shared defaults on PPC64LE. OSR root
  prologs inherit the Tier0 frame, restore Tier0 callee-saves from the inherited
  frame pointer, restore LR from `8(FP)`, and report phantom unwind allocation
  for the Tier0 frame.
- PPC64LE patchpoints call the helper via `mtctr; bctrl`; the helper sees the
  return address immediately after `bctrl`. The no-transition continuation skips
  the generated `mtctr; bctr` tail.
- `EnableWriteXorExecute` defaults to `0` on PPC64LE during qemu/binfmt
  testing.
- CoreCLR R2R reverse P/Invoke remains unsupported.
- CoreCLR R2R PPC64LE TOC/GOT relocation forms are guarded against. See the
  [PPC64LE ABI](jit/ppc64le-abi.md) for the relocation contract.
- SIMD/VSX is blocked for PPC64LE until JIT and runtime support are implemented.

Do not remove a gate without adding a focused validation plan for the code path
being enabled.

## TOC And Entry-Point Rules

The authoritative TOC, entry-point, helper, P/Invoke, reverse P/Invoke, and
tailcall contract is [PPC64LE ABI](jit/ppc64le-abi.md). Keep ABI decisions
there; keep this bring-up document focused on test commands, failure diagnosis,
and remaining implementation gaps.

## Frame, Unwind, And Hijacking Rules

Frame layout follows PPC64 ELFv2 linkage conventions. The caller linkage area
remains at the top of the stack, and the JIT reserves ABI-sensitive slots such
as the TOC save slot at offset 24 from SP for unmanaged calls that can clobber
`r2`.

Frame invariants to re-check after prolog/epilog or unwind changes:

- SP points at the active linkage area whenever unmanaged ABI code can observe
  the frame.
- Saved LR, saved `r2`, callee-saved registers, outgoing argument space, and
  local slots agree between JIT codegen, unwind info, and NativeAOT code
  manager logic.
- Split SP adjustment still leaves callee-save offsets encodable at the
  instruction that saves or restores them.
- Epilog recognition covers normal methods and funclets.
- `TrailingEpilogueInstructionsCount`, hijack offset calculation, DWARF CFI,
  and NativeAOT `UnixNativeCodeManager` epilog recognition stay in sync.

Return-address hijacking depends on exact LR location. PPC64LE exposes saved
link-register stack locations through `KNONVOLATILE_CONTEXT_POINTERS::Link`.
Hijacking must decline frames when unwind data only points `Link` at the copied
context value, when no saved link location is available, or when the frame has
tailcalls.

`RhpGcProbeHijack` is entered by overwriting a return address. It must preserve
valid return values and avoid clobbering registers or stack locations that may
hold the interrupted method's return state. Keep the fast path minimal; build a
proper probe frame before making calls on the slow path.

## JIT Debugging

Use checked JIT/runtime builds whenever possible:

```sh
CORE_ROOT=$PWD/artifacts/tests/coreclr/linux.ppc64le.Checked/Tests/Core_Root \
DOTNET_ReadyToRun=0 \
DOTNET_TieredCompilation=0 \
DOTNET_JitDump='<method-pattern>' \
DOTNET_JitGCDump='<method-pattern>' \
DOTNET_JitDisasm='<method-pattern>' \
DOTNET_JitDisasmWithGC=1 \
DOTNET_JitDisasmWithAddress=1 \
DOTNET_JitStdOutFile=/tmp/ppc-jitdump.log \
$CORE_ROOT/corerun <repro>.dll
```

For NativeAOT ILC JIT dumps, use focused codegen options:

```text
--codegenopt "JitDump=<method-pattern>" --codegenopt JitGCDump=1
```

When debugging JIT behavior, compare the PPC64LE shape against x64, ARM64, and
RISC-V before adding PPC-only codegen. Other architectures often avoid symptoms
through normal lowering, containment, call-target handling, or GC-state updates.
When host execution is not enough, build crossjits such as RISC-V and use
AltJit plus `JitDump` to compare non-host target lowering and codegen shapes
against PPC64LE.

Useful checks in a JIT dump:

- ABI argument and return classification.
- Split struct parameter homes and callee-save save slots do not overlap.
- GC live ranges for registers and stack slots around calls, helper calls, and
  interruptible points.
- No-GC windows have accurate state immediately before and after the window.
- Hidden scratch registers introduced by emitter expansions produce matching
  GC-dead transitions when they clobber volatile GC registers.
- PPC DS-form load/store offsets are aligned as well as in range.
- Address containment agreed between lowering, LSRA, codegen, and emitter.

Prefer `powerpc64le-linux-gnu-objdump` over `llvm-objdump` for PPC64LE
disassembly during bring-up:

```sh
powerpc64le-linux-gnu-objdump -d -j __managedcode <binary>
```

Build tests with `StripSymbols=false` when native disassembly or core triage is
expected.

## GC Stress Debugging

For flaky CoreCLR or NativeAOT failures under GC stress, assume GC corruption
until evidence points elsewhere. Reduced concurrency can lower noise, but
`DOTNET_PROCESSOR_COUNT=1` is not a root-cause signal by itself.

CoreCLR stress command template:

```sh
ulimit -c unlimited
rm -f /tmp/perf-*.map

CORE_ROOT=$PWD/artifacts/tests/coreclr/linux.ppc64le.Checked/Tests/Core_Root \
DOTNET_ReadyToRun=0 \
DOTNET_TieredCompilation=0 \
DOTNET_GCStress=0x4 \
DOTNET_PerfMapEnabled=1 \
DOTNET_StressLog=1 \
DOTNET_StressLogSize=1048576 \
DOTNET_TotalStressLogSize=67108864 \
DOTNET_LogLevel=9 \
COMPlus_PerfMapEnabled=1 \
COMPlus_StressLog=1 \
COMPlus_StressLogSize=1048576 \
COMPlus_TotalStressLogSize=67108864 \
COMPlus_LogLevel=9 \
$CORE_ROOT/corerun <test-or-repro>.dll
```

NativeAOT stress command template:

```sh
DOTNET_GCStress=0xC \
DOTNET_StressLog=1 \
DOTNET_TotalStressLogSize=67108864 \
DOTNET_StressLogLevel=9 \
GLIBC_TUNABLES=glibc.rtld.optional_static_tls=128000 \
<nativeaot-test-command>
```

Use `DOTNET_gcConservative=1` to split precise GC reporting holes from other
state corruption. If conservative reporting fixes the repro, inspect precise
stack and register GC info. If it does not, inspect hijacking, transition
frames, statics/TLS, helper ABIs, register preservation, and unmanaged
boundaries.

Useful artifacts for GC-hole reports:

- Minimized command and full environment.
- qemu `.core` file, if any.
- `/tmp/perf-<pid>.map`.
- Matching binaries and `.dbg` files.
- Raw and decoded stress-log chunks.
- JIT dumps for top managed frames, with `JitGCDump=1`.
- A table of suspect stack slots and registers: location, method, GC type,
  tracked/untracked state, and corrupted value.

Stress-log workflow:

1. Find the bad object reference, stack location, or register value near the
   failure.
2. Walk backward through the previous GCs to find where that location was last
   reported.
3. Record stopped threads, managed IPs, interruptible/prolog/epilog state, and
   reported roots for each suspect frame.
4. Map managed IPs through `/tmp/perf-<pid>.map` or NativeAOT symbol ranges.
5. Generate a focused JIT dump and compare GC info with disassembly at the
   stopped IP.

Bad values have different meanings:

- Small integers or partial constants often indicate a missing GC-dead
  transition for an emitter-expanded scratch register.
- Stack addresses or code addresses usually mean the location was misclassified
  as a GC reference.
- Fill patterns such as `0xcdcdcdcdcdcdcdcd` usually mean an uninitialized or
  poisoned location reached a reporting path.
- Stale interior pointers often point to outgoing argument, byref, or fixed
  outgoing-arg pseudo-local reporting mistakes.

## Core Dumps And Debuggers

Enable qemu core dumps before running crash repros:

```sh
ulimit -c unlimited
```

qemu-user cores commonly use names like:

```text
qemu_<guest-exe>_<YYYYMMDD-HHMMSS>_<qemu-pid>.core
```

These are often more reliable than live debugger sessions. SIG34 is used by
NativeAOT thread hijacking during stop-the-world and is usually noise.

Load a qemu core with:

```sh
gdb-multiarch -nx -nh -q \
    -iex 'set pagination off' \
    -iex 'set debug-file-directory /tmp/no-debug-files' \
    -iex 'set debuginfod enabled off' \
    -iex 'set auto-solib-add off' \
    $CORE_ROOT/corerun qemu_corerun_*.core
```

Map native runtime PCs through matching debug images:

```sh
addr2line -Cfipe $CORE_ROOT/libcoreclr.so.dbg <libcoreclr-offset>
```

For qemu-user with a GDB stub:

```sh
qemu-ppc64le -g 1234 <guest-exe> <args>
gdb-multiarch <guest-exe>
```

```text
(gdb) target remote :1234
(gdb) handle SIG34 nostop noprint pass
(gdb) continue
```

## StressLog Capture Helpers

Prefer raw chunk dumps over interactive formatted output. Raw chunks can be
decoded repeatedly while the process/core state remains stable.

Decode NativeAOT stress-log chunks:

```sh
python3 src/tools/StressLogAnalyzer/scripts/decode_nativeaot_stresslog.py \
    /tmp/stresslog-capture \
    --module <nativeaot-elf> \
    --output /tmp/stresslog.txt
```

GDB capture:

```text
(gdb) set pagination off
(gdb) handle SIG34 nostop noprint pass
(gdb) source src/tools/StressLogAnalyzer/scripts/dump_nativeaot_stresslog_gdb.py
(gdb) dump_nativeaot_stresslog /tmp/stresslog-capture
```

LLDB capture:

```text
(lldb) process handle -p true -n false -s false SIG34
(lldb) command script import src/tools/StressLogAnalyzer/scripts/dump_nativeaot_stresslog_lldb.py
(lldb) dump_nativeaot_stresslog /tmp/stresslog-capture
```

Manual fallback:

- Find globals with `info variables StressLog`, `info variables theLog`, or
  `image lookup -rn StressLog`.
- Confirm layouts with `ptype StressLog`, `ptype ThreadStressLog`, and
  `ptype StressLogChunk`.
- Dump each chunk with GDB `dump binary memory` or LLDB
  `memory read --binary --outfile`.

## JIT And ABI Design Decisions

Struct classification:

- `VarTypeIsMultiByteAndCanEnreg` must match the PPC64LE ABI.
- Small aggregates may use multiple integer/floating return registers.
- Larger or non-enregisterable structs use hidden return buffers.
- Managed aggregate returns use the CoreCLR managed ABI cap of two eight-byte
  return slots. PPC64LE HFA returns larger than 16 bytes are native interop ABI
  shapes only; managed calls must use a hidden return buffer for those structs.
- For unmanaged returns, only homogeneous floating-point aggregates use FPR
  return registers. Mixed floating-point/integer aggregates are not HFAs in the
  ELFv2 ABI and must return through integer chunks in `r3/r4`.
- `MethodTable::GetFpStructInRegistersInfo`/`FpStructInRegistersInfo` are the
  central runtime description for RISC-V/LoongArch two-field FP structs and
  PPC64LE HFAs. `CEEInfo::getFpStructLowering`, NativeAOT `CorInfoImpl`, and
  the VM argument iterator should consume that description instead of
  rediscovering PPC64LE HFA shape locally.
- Split multireg struct parameters should not overlap callee-saved save slots.
- If a struct contains GC references, every intermediate copy location must be
  non-GC by construction or reported for the full live range.

Calls and helpers:

- A no-GC helper is not a no-clobber helper.
- Volatile registers holding GC refs across a no-GC helper must be dead,
  spilled to reported locations, or preserved by a documented helper ABI.
- Write-barrier and assignment-helper `AVLocation` labels must stay immediately
  attached to the faulting memory access used for null-reference recognition.
- Helper kill sets, `GT_START_NONGC`/`GT_START_PREEMPTGC`, and call-site GC
  labels must be audited together.

TOC, branch-target, dispatch-stub, and fast-tailcall register-selection rules
are documented in [PPC64LE ABI](jit/ppc64le-abi.md).

ABI stress:

- `JIT/Stress/ABI` has a PPC64LE model for scalar, small aggregate, calli,
  stub, and managed tailcall stress. SIMD/VSX types are intentionally excluded.
- Managed tailcall stress uses scalar and <=16-byte aggregate candidates so it
  exercises the managed ABI and fast-tailcall path without requiring native HFA
  or large-struct tailcall support.
- Unmanaged integer aggregates can split as a register prefix plus one stack
  tail. Prolog homing and outgoing stack copies must handle stack segments
  larger than one pointer-sized slot.
- Delegate/reverse P/Invoke by-value large struct marshalling uses the same
  ELFv2 aggregate rule: unmanaged aggregates consume remaining `r3`-`r10`
  slots and put the tail in the parameter save area. Large stack tails should
  be copied as a block rather than expanded into a huge `FIELD_LIST`.

Profiler enter/leave/tailcall hooks:

- PPC64LE supports the slow-path ICorProfiler ELT hooks through
  `ProfileEnterNaked`, `ProfileLeaveNaked`, and `ProfileTailcallNaked`.
- The JIT stages the profiler function id in `r12` and the profiled caller SP
  in `r0`, then stores both in the caller linkage/parameter area before
  calling the naked helper. The helper reloads these values before allocating
  its own profiler frame.
- The naked helper saves `r3`-`r10` and `f1`-`f13` into
  `PROFILE_PLATFORM_SPECIFIC_DATA`, calls the shared profiler helper, and
  restores those registers before returning. This preserves argument registers
  for enter hooks and return registers for leave hooks.
- Save the incoming `r11` before using it as helper scratch. Leave/tailcall
  probes are injected late and PPC64LE codegen can still have a live helper
  byref or tailcall target in `r11` around the probe.
- PPC64LE profiler return-value classification uses
  `ArgIterator::GetReturnFpStructInRegistersInfo()` so HFA and mixed FP/integer
  return values follow the same central ABI classification used by calls.

## Current Implementation Gaps

Keep this list current. Remove items when the code path is enabled and covered
by useful validation.

- Varargs are not implemented in the PPC64LE ABI classifier and
  `genJmpPlaceVarArgs`.
- Fast and portable tailcalls are enabled for managed calls. Keep split
  register/stack fast tailcall arguments rejected until the PPC64LE stack
  argument shuffle is designed and tested.
- Delegate invoke fast tailcalls are blocked after `test76531` exposed a hang
  in the VSD resolve/shuffle-stub path. Re-enable only after a targeted stub
  audit explains the epilog+jump interaction and covers open-interface
  delegates.
- Profiler hook validation should be broadened beyond the focused ELT and
  inlining tests. In particular, recheck unwind/prolog agreement for the naked
  profiler helpers before relying on profiler stack walking diagnostics.
- SIMD/VSX and hardware intrinsics are not implemented.
- Floating-point callee-saved registers F14-F31 are not available to LSRA until
  prolog/epilog save and restore support is implemented.
- Byte and short `Interlocked.*` overloads still fall back to helpers.
- Large stack-frame and large local-offset coverage exists for local GC ref
  stores, contained local addresses, outgoing stack argument copies, and
  unaligned signed 32-bit loads. Keep extending `JIT/Methodical/largeframes`
  whenever another large-offset NYI is found; fixes should preserve emitter
  local-var metadata rather than falling back to raw base+offset stores.
- CoreCLR R2R reverse P/Invoke needs a loader/JIT/runtime entrypoint design
  before it is enabled. See [PPC64LE ABI](jit/ppc64le-abi.md).
- CoreCLR R2R PPC64LE TOC/GOT relocation forms are intentionally blocked. See
  [PPC64LE ABI](jit/ppc64le-abi.md) for the file-format contract.
- Inline TLS access sequences need continued validation; the glibc static-TLS
  tunable is only a test-environment workaround.
