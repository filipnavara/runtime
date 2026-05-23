# PPC64LE NativeAOT TOC ABI

NativeAOT follows the PPC64 ELFv2 TOC model.

In NativeAOT, compiled managed code, generated stubs, and NativeAOT runtime
helpers are emitted into ELF objects and linked by the native linker. The
linker owns the final module TOC, and `r2` has the normal ELFv2 meaning for the
current native image.

## Entry Points

PPC64 ELFv2 distinguishes global and local entry points:

- A global entry may establish `r2` from `r12`. External callers enter here and
  must set `r12` to the callee entry address.
- A local entry assumes `r2` already contains the callee module's TOC.
  Same-module calls may branch to the local entry and preserve the current TOC.

NativeAOT PPC64LE reverse P/Invoke and `[UnmanagedCallersOnly]` method bodies
use the canonical two-instruction `.TOC.` sequence in the method prolog:

```asm
addis 2, 12, .TOC.-entry@ha
addi  2, 2,  .TOC.-entry@l
```

The ELF object writer marks such method symbols with localentry 8 so the linker
and same-module call sites can distinguish the global TOC-establishing entry
from the local entry.

## Relocations

NativeAOT may use PPC64 TOC-relative relocations because the native ELF linker
defines `.TOC.` and resolves the TOC relocation pairs:

- `PPC64_TOC16` addresses image-local data through `r2`.
- `PPC64_REL16_TOC` materializes the current method's TOC from the global entry
  address in `r12`.
- GOT and TLS relocation forms are native ELF relocations and are handled by the
  linker or dynamic loader according to ELFv2.

The `.TOC.` symbol is an ELF linker concept in NativeAOT. It must not be
assumed to exist for CoreCLR ReadyToRun PE images.

## Runtime Helpers

NativeAOT runtime assembly helpers are in the native image TOC domain. Helpers
may use `r2` for `@toc` loads when they are entered with the image TOC already
established.

Cross-module helper calls must follow normal ELFv2 rules: call the global entry
with `r12` holding the helper entry address, and restore the caller TOC if the
caller continues to execute in a different TOC domain after the call.

Assembly labels that are only local entries must not be exported as cross-TOC
targets. If a helper needs to be callable from another TOC domain, provide a
global-entry wrapper or a transition thunk that establishes the helper's TOC.

## P/Invoke

NativeAOT managed-to-native calls satisfy the native boundary by using the
ELFv2 global-entry convention:

- Save the managed/native image `r2` if execution will return to code that
  relies on it.
- Place the unmanaged target entry address in `r12`.
- Branch through CTR.
- Restore `r2` after a returning call when required.

Direct calls may use GOT-based address loads. Indirect calls still branch
through `r12` so a target global entry can derive its TOC correctly.

## Reverse P/Invoke

Reverse P/Invoke entries are native ELFv2 entries. External unmanaged callers
enter with `r12` holding the method entry address. The method prolog establishes
the NativeAOT image TOC in `r2` before any TOC-relative access.

Same-image NativeAOT callers may call the method's local entry when the current
TOC is already the callee TOC. They must not enter the local entry from another
TOC domain.

## Tailcalls

Tailcall helpers cannot rely on a return path to repair `r2`. Before branching,
a tailcall helper must ensure the final target sees the TOC it expects:

- Same-image NativeAOT targets may be tailcalled with the current image TOC.
- Cross-module native targets must be entered through the ELFv2 global-entry
  convention with `r12` holding the target entry address.
- A helper that tailcalls after temporarily switching TOC domains must either
  restore the caller/final-target TOC or establish the target TOC explicitly.
