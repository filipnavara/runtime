// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

using ILCompiler.DependencyAnalysis.Ppc64le;

namespace ILCompiler.DependencyAnalysis.ReadyToRun
{
    /// <summary>
    /// This node emits a thunk calling DelayLoad_Helper with a given instance signature
    /// to populate its indirection cell.
    /// </summary>
    public partial class ImportThunk
    {
        protected override void EmitCode(NodeFactory factory, ref Ppc64leEmitter instructionEncoder, bool relocsOnly)
        {
            if (_thunkKind == ImportThunkKind.Eager)
            {
                instructionEncoder.EmitJMP(_helperCell);
                return;
            }

            if (relocsOnly)
            {
                // When doing relocs only, we don't need the exact instruction stream.
                // Emit the module import load and helper jump so the dependencies are recorded.
                instructionEncoder.EmitLD(instructionEncoder.TargetRegister.Arg1, factory.ModuleImport);
                instructionEncoder.EmitJMP(_helperCell);
                return;
            }

            switch (_thunkKind)
            {
                case ImportThunkKind.DelayLoadHelper:
                case ImportThunkKind.DelayLoadHelperWithExistingIndirectionCell:
                case ImportThunkKind.VirtualStubDispatch:
                    // r12 contains the indirection cell on entry and is consumed by the
                    // delay-load assembly helpers as their first scratch argument.

                    // r11 contains the import section index.
                    instructionEncoder.EmitLI(Register.R11, _containingImportSection.IndexFromBeginningOfArray);

                    // r10 contains Module*.
                    instructionEncoder.EmitLD(Register.R10, factory.ModuleImport);
                    break;

                case ImportThunkKind.Lazy:
                    // Lazy string helper expects Module* in the second argument register.
                    instructionEncoder.EmitLD(instructionEncoder.TargetRegister.Arg1, factory.ModuleImport);
                    break;

                default:
                    throw new NotImplementedException();
            }

            instructionEncoder.EmitJMP(_helperCell);
        }
    }
}
