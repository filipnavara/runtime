# PPC64LE CoreCLR TOC ABI

PPC64 ELFv2 uses `r2` as the table-of-contents (TOC) register. Normal ELF code
assumes `r2` points at the current ELF module's TOC, and global-entry calls
arrive with `r12` containing the callee entry address so the callee can derive
its own TOC.

CoreCLR managed code uses an explicit managed ABI instead of inheriting the
ELFv2 model accidentally. In CoreCLR managed code, including JIT code and
ReadyToRun code, `r2` is the CoreCLR runtime module TOC. Managed methods
preserve `r2` across managed-to-managed calls.

Every boundary must satisfy this rule:

At a boundary, `r2` must either already mean what the callee expects, or the
boundary code must establish it before entering the callee.

## Domains

### CoreCLR JIT Code

Normal non-relocating CoreCLR JIT code keeps `r2` as the CoreCLR runtime TOC.
It materializes managed addresses without TOC-relative relocations. Managed-to-
managed calls therefore do not require a TOC setup in the callee prolog, and
direct managed call targets must not be adjusted by an ELFv2 local-entry offset.

Because `r2` already has the runtime TOC, JIT code can call runtime helpers that
expect the `libcoreclr.so` TOC without a helper-specific TOC switch. Helpers
must still preserve `r2` if they return to managed code.

JIT code must still use ELFv2-shaped call sequences at native boundaries.
Indirect calls that might enter native code branch through `r12`, because
PPC64 ELFv2 global entries derive the callee TOC from `r12`.

### CoreCLR ReadyToRun Code

PPC64LE CoreCLR ReadyToRun uses the same managed ABI as CoreCLR JIT code:
`r2` is the CoreCLR runtime TOC at managed entry, throughout managed execution,
and at managed exit. R2R-to-JIT and JIT-to-R2R calls are ordinary managed calls
and do not switch TOC domains.

The current PPC64LE reloc-mode emitter uses `r2` for TOC-relative address
materialization. NativeAOT can satisfy that contract through ELF linking, but
CoreCLR ReadyToRun images are PE-format managed images. They must not use `r2`
as an R2R-image TOC because that would conflict with the managed ABI's runtime
TOC rule.

Until the PPC64LE emitter has a CoreCLR R2R relocation materialization strategy
that does not consume `r2`, the JIT rejects PPC64LE CoreCLR R2R compilation
instead of emitting code that would reinterpret `r2` as an image-local TOC.

A future CoreCLR R2R design must define all of the following before R2R can be
enabled:

- How R2R code materializes image-local addresses, import cells, and fixup
  cells without using `r2`.
- How generated R2R entrypoints verify or establish the runtime TOC when
  entered from native transition stubs.
- How R2R relocations represent the chosen non-TOC address materialization.
- How cross-image managed calls preserve the runtime TOC.
- How calls into CoreCLR runtime helpers preserve the runtime TOC on return.
- How tailcall helpers establish the final target's expected TOC before
  branching.
- How reverse P/Invoke entries establish the runtime TOC before entering R2R
  code, or which fallback thunk/JIT path owns reverse P/Invoke for R2R.

## Runtime Helpers

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

## P/Invoke

Managed-to-native calls must satisfy ELFv2 at the native boundary:

- The native target entry address is placed in `r12`.
- The call branches through CTR.
- The runtime TOC in `r2` is saved before the call.
- The runtime TOC is restored after a returning call.

Indirect unmanaged calls use the same convention. Helper paths such as
`CORINFO_HELP_PINVOKE_CALLI` must not treat `r12` as a casual scratch register;
if `r12` carries the unmanaged target, the helper ABI must preserve that value
or move it to a documented parameter register before loading the helper target.

## Reverse P/Invoke

CoreCLR reverse P/Invoke entries must establish the runtime TOC before entering
managed code. JIT-generated reverse P/Invoke bodies can rely on the runtime's
entry thunk or call path to provide this; they do not use an image-local managed
TOC.

CoreCLR R2R reverse P/Invoke is unsupported until the R2R entry contract exists.
When enabled, one of these must be true:

- The runtime creates a reverse P/Invoke thunk that establishes the runtime TOC
  before entering the R2R method.
- The R2R entrypoint has a prolog that establishes the runtime TOC without
  consuming an image-local TOC.
- R2R declines to own reverse P/Invoke and falls back to a JIT/runtime-generated
  entry.

## Tailcalls

Tailcall helpers do not return to a caller that can repair `r2`. A tailcall
helper must branch only after establishing the TOC expected by the final target.
If the final target is a native ELFv2 global entry, the helper must branch
through `r12` with `r12` holding the target entry address. If the final target
is CoreCLR managed code, the helper must branch with `r2` containing the runtime
TOC.
