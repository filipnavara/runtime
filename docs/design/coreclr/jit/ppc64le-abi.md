# PPC64LE ABI

PPC64 ELFv2 uses `r2` as the table-of-contents (TOC) register. Normal ELF code
assumes `r2` points at the current ELF module's TOC. Calls to global entry
points arrive with `r12` containing the callee entry address so the callee can
derive its own TOC.

CoreCLR and NativeAOT use different TOC models:

- CoreCLR JIT and ReadyToRun managed code use an explicit managed ABI where
  `r2` is the `libcoreclr.so` runtime TOC.
- NativeAOT follows the platform ELFv2 model where `r2` is the current native
  image TOC.

Every boundary follows one rule:

At a boundary, `r2` must either already mean what the callee expects, or the
boundary code must establish it before entering the callee.

## ELFv2 Entry Points

PPC64 ELFv2 distinguishes global and local entry points:

- A global entry may establish `r2` from `r12`. External callers enter here and
  must set `r12` to the callee entry address.
- A local entry assumes `r2` already contains the callee module's TOC.
  Same-module calls may branch to the local entry and preserve the current TOC.

Any indirect branch or call that can cross into ELFv2 code must branch through
`r12`, and the callee may use `r12` to establish its TOC.

## CoreCLR Managed TOC ABI

CoreCLR managed code, including JIT and ReadyToRun code, keeps `r2` as the
CoreCLR runtime TOC at managed entry, throughout managed execution, and at
managed exit. Managed methods preserve `r2` across managed-to-managed calls.

Normal non-relocating JIT code materializes managed addresses without
TOC-relative relocations. Managed-to-managed calls therefore do not require a
TOC setup in the callee prolog, and direct managed call targets must not be
adjusted by an ELFv2 local-entry offset.

Because managed `r2` already has the runtime TOC, JIT and R2R code can call
runtime helpers that expect the `libcoreclr.so` TOC without a helper-specific
TOC switch. Helpers must still preserve `r2` if they return to managed code.

JIT-to-R2R and R2R-to-JIT calls are ordinary managed calls and do not switch TOC
domains.

## CoreCLR ReadyToRun

CoreCLR ReadyToRun images are PE-format managed images. They must not use `r2`
as an R2R-image TOC because that would conflict with the CoreCLR managed ABI's
runtime TOC rule. PPC64LE CoreCLR R2R therefore uses PC-relative
materialization for image-local addresses, import cells, and fixup cells.

The compiler and object writer must reject PPC64LE R2R relocation forms that
derive addresses from a TOC or GOT:

- `PPC64_TOC16`
- `PPC64_REL16_TOC`
- `PPC64_GOT_TPREL16`
- `PPC64_GOT16`

R2R may use explicit non-TOC PPC64 relocations such as `PPC64_REL16` and
`PPC64_REL24`. If additional R2R-specific relocation forms become necessary,
they should be modeled as explicit PE/R2R file-format concepts rather than
pretending the PE image has an ELF `.TOC.` symbol.

PPC64LE HA/LO relocation pairs should be represented as one logical relocation
at the JIT/object-writer boundary. The object writer may expand a logical
relocation into `_HA` and `_LO` records, but generic relocation records should
not carry ad hoc half-pair addends.

CoreCLR R2R reverse P/Invoke is unsupported until the R2R entry contract exists.
When enabled, one of these must be true:

- The runtime creates a reverse P/Invoke thunk that establishes the runtime TOC
  before entering the R2R method.
- The R2R entrypoint has a prolog that establishes the runtime TOC without
  consuming an image-local TOC.
- R2R declines to own reverse P/Invoke and falls back to a JIT/runtime-generated
  entry.

## CoreCLR Helper And Stub Registers

Register roles that affect TOC and branch boundaries:

- `r12` is the canonical ELFv2 branch-target register. Any indirect branch,
  call, or jump that can enter an ELFv2 global entry must place the final target
  in `r12` and branch with `mtctr r12; bctr/bctrl`.
- `r11` carries CoreCLR non-standard call state: secret stub parameters, R2R
  indirection cells, virtual-stub dispatch cells, P/Invoke cookies, precode
  tokens, and call-counting state. Do not use `r11` as general epilog or branch
  scratch when any of those paths can still be live.
- `r0` may be used for private helper state that must survive the helper target
  load into `r12`, such as the P/Invoke calli unmanaged target.

Write-barrier helpers have their own fixed-register contract:

- Normal write barriers use `r11` for the destination/byref destination and
  `r10` for the source reference.
- Byref write barriers use `r11` for the destination/byref destination and
  `r9` for the byref source. The helper loads the referenced object into `r10`
  before entering the checked write-barrier path.
- The PPC64LE write-barrier helpers may post-increment `r11`, but keep it as a
  valid byref. The JIT kill sets must not report `r11` as GC-dead for the
  normal write-barrier helper.

Runtime helpers belong to one of three TOC domains:

- Managed-domain helpers are callable with the CoreCLR managed `r2` value,
  which is the runtime TOC.
- Runtime-domain helpers require the `libcoreclr.so` TOC. CoreCLR managed code
  already satisfies this requirement. These helpers must preserve `r2` if they
  return to managed code.
- Transition and tailcall helpers must document the TOC they consume and the TOC
  they establish before branching.

Assembly helpers declared with the shared `LEAF_ENTRY` or `NESTED_ENTRY` macros
are local-entry-only unless they explicitly establish `r2`. They must not be
used directly as cross-TOC targets.

Compiler-generated C++ functions in `libcoreclr.so` have normal ELFv2 global
entries. Managed code may call them with the runtime TOC already in `r2`.
Indirect calls should still load the callee entry address into `r12` and branch
through CTR so the sequence remains valid for global-entry targets.

Runtime assembly stubs that call C++ while entered from managed code save the
caller `r2`, establish the `libcoreclr.so` TOC from a local PC, call the worker,
then restore the saved `r2` before returning or before tailcalling to a managed
target.

### Delay-Load And Dispatch Stubs

R2R delay-load import thunks must not use managed argument registers for thunk
metadata. On PPC64LE the thunk enters the delay-load helper with:

- `r11`: the indirection cell, matching the managed call-site convention.
- `r12`: the owning `Module*`.
- `r0`: the import section index.

The delay-load helper saves `r0` before creating the transition block, then
establishes the runtime TOC locally before calling the VM worker. After the
worker resolves the target, the helper restores the caller's runtime TOC before
returning or tailcalling to managed code.

Interface dispatch keeps the dispatch cell in `r11`. Dispatch stubs use `r12`
for cache/target scratch so fast-path and slow-path calls branch with `r12` set
to the callee entry. Instantiating method stubs shuffle arguments, materialize
the hidden instantiation argument, adjust boxed `this` for unboxing stubs, and
tailcall through `r12`. Precode and call-counting stubs keep secret parameters
or tokens in `r11`, leaving `r12` for the branch target.

Stub-linker label calls and tailcalls materialize the label through an adjacent
literal, leave the final target in `r12`, then branch using `mtctr r12`
followed by `bctr` or `bctrl`. This matches the CoreCLR managed TOC rule
because `r2` is not touched, and it matches the ELFv2 branch-target rule
because global entries observe `r12` holding the target address.

## CoreCLR P/Invoke

Managed-to-native calls must satisfy ELFv2 at the native boundary:

- Save the managed runtime TOC in `r2` before the call.
- Put the unmanaged target entry address in `r12`.
- Branch through CTR.
- Restore the managed runtime TOC in `r2` after a returning call.

Indirect unmanaged calls use the same convention.

The P/Invoke calli unmanaged target is staged in `r12` for LSRA, then copied to
`r0` immediately before the helper call because `r12` must contain the ELFv2
helper entry point on entry. The helper consumes `r0` as the unmanaged target
and uses `r11` for the `VASigCookie` before publishing the generated-stub secret
argument in `r11`. This keeps private helper state out of the native argument
register set, including native argument `r10`.

## CoreCLR Reverse P/Invoke

CoreCLR reverse P/Invoke entries must establish the runtime TOC before entering
managed code. JIT-generated reverse P/Invoke bodies can rely on the runtime's
entry thunk or call path to provide this; they do not use an image-local managed
TOC.

Under PPC64 ELFv2, a caller that performs a global call is responsible for
preserving its own `r2` if it needs the old TOC after the call. A reverse
P/Invoke global entry may establish the CoreCLR runtime TOC from `r12` without
restoring the native caller's TOC on return.

## CoreCLR Tailcalls

Tailcall helpers do not return to a caller that can repair `r2`. A tailcall
helper must branch only after establishing the TOC expected by the final target.
If the final target is a native ELFv2 global entry, the helper must branch
through `r12` with `r12` holding the target entry address. If the final target
is CoreCLR managed code, the helper must branch with `r2` containing the runtime
TOC.

Managed fast tailcalls preserve the CoreCLR runtime TOC in `r2`. `r11` is not
available as a tailcall epilog scratch register because virtual-stub dispatch
cells, R2R indirection cells, and other non-standard arguments can remain live
in `r11` until the final branch.

`r12` may be used as a tailcall epilog scratch register only before the final
target is materialized. The final target load or move must happen after the
epilog has restored callee-saves, SP, and LR, and the emitted branch must still
be `mtctr r12; bctr`.

Fast-tailcall control expressions and temporary loaded call targets must avoid
`r12`, because the epilog can clobber it before the final target load or move.

Delegate invokes are currently rejected for PPC64LE fast tailcall formation. A
`test76531` hang showed that the epilog-and-jump path still has an unresolved
interaction with delegate invoke targets that can enter VSD resolve/shuffle
stubs. Normal delegate invokes and explicit tailcalls through the helper path
remain the conservative route until that stub contract is audited.

PPC64LE call lowering distinguishes the ABI-mandated 64-byte parameter save area
from actual stack-passed arguments. Fast-tailcall stack-space checks use only
the raw classified stack-argument byte count; normal outgoing call frame sizing
still reserves the full save area. Fast tailcalls that need stack arguments
require a materialized incoming stack-argument local at offset zero. If the
caller's first stack slots are consumed only by FPR parameter slots, the JIT
rejects the fast tailcall and uses the helper path instead.

## NativeAOT TOC ABI

NativeAOT follows the PPC64 ELFv2 TOC model.

In NativeAOT, compiled managed code, generated stubs, and NativeAOT runtime
helpers are emitted into ELF objects and linked by the native linker. The
linker owns the final module TOC, and `r2` has the normal ELFv2 meaning for the
current native image.

NativeAOT PPC64LE reverse P/Invoke and `[UnmanagedCallersOnly]` method bodies
use the canonical two-instruction `.TOC.` sequence in the method prolog:

```asm
addis 2, 12, .TOC.-entry@ha
addi  2, 2,  .TOC.-entry@l
```

The ELF object writer marks such method symbols with localentry 8 so the linker
and same-module call sites can distinguish the global TOC-establishing entry
from the local entry.

### NativeAOT Relocations

NativeAOT may use PPC64 TOC-relative relocations because the native ELF linker
defines `.TOC.` and resolves the TOC relocation pairs:

- `PPC64_TOC16` addresses image-local data through `r2`.
- `PPC64_REL16_TOC` materializes the current method's TOC from the global entry
  address in `r12`.
- GOT and TLS relocation forms are native ELF relocations and are handled by the
  linker or dynamic loader according to ELFv2.

The `.TOC.` symbol is an ELF linker concept in NativeAOT. It must not be
assumed to exist for CoreCLR ReadyToRun PE images.

### NativeAOT Helpers

NativeAOT runtime assembly helpers are in the native image TOC domain. Helpers
may use `r2` for `@toc` loads when they are entered with the image TOC already
established.

Cross-module helper calls must follow normal ELFv2 rules: call the global entry
with `r12` holding the helper entry address, and restore the caller TOC if the
caller continues to execute in a different TOC domain after the call.

Assembly labels that are only local entries must not be exported as cross-TOC
targets. If a helper needs to be callable from another TOC domain, provide a
global-entry wrapper or a transition thunk that establishes the helper's TOC.

NativeAOT runtime wrappers should own calls to true external libc/libm symbols
when managed or helper call sites need to remain in-module.

### NativeAOT P/Invoke And Reverse P/Invoke

NativeAOT managed-to-native calls satisfy the native boundary by using the
ELFv2 global-entry convention:

- Save the managed/native image `r2` if execution will return to code that
  relies on it.
- Place the unmanaged target entry address in `r12`.
- Branch through CTR.
- Restore `r2` after a returning call when required.

Direct calls may use GOT-based address loads. Indirect calls still branch
through `r12` so a target global entry can derive its TOC correctly.

Reverse P/Invoke entries are native ELFv2 entries. External unmanaged callers
enter with `r12` holding the method entry address. The method prolog establishes
the NativeAOT image TOC in `r2` before any TOC-relative access.

Same-image NativeAOT callers may call the method's local entry when the current
TOC is already the callee TOC. They must not enter the local entry from another
TOC domain.

### NativeAOT Tailcalls

Tailcall helpers cannot rely on a return path to repair `r2`. Before branching,
a tailcall helper must ensure the final target sees the TOC it expects:

- Same-image NativeAOT targets may be tailcalled with the current image TOC.
- Cross-module native targets must be entered through the ELFv2 global-entry
  convention with `r12` holding the target entry address.
- A helper that tailcalls after temporarily switching TOC domains must either
  restore the caller/final-target TOC or establish the target TOC explicitly.

## Frame And Save Slots

Frame layout follows PPC64 ELFv2 linkage conventions. The caller linkage area
remains at the top of the stack, and the JIT reserves ABI-sensitive slots such
as the TOC save slot at offset 24 from SP for unmanaged calls that can clobber
`r2`.

After prolog/epilog or unwind changes, re-check that saved LR, saved `r2`,
callee-saved registers, outgoing argument space, and local slots agree between
JIT codegen, unwind info, and NativeAOT code-manager logic.
