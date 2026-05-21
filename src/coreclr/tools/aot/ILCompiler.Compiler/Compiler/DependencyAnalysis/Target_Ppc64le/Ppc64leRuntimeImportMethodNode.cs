// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using ILCompiler.DependencyAnalysis.Ppc64le;
using ILCompiler.DependencyAnalysisFramework;

using Internal.Text;
using Internal.TypeSystem;
using Internal.TypeSystem.Ecma;

using Debug = System.Diagnostics.Debug;

namespace ILCompiler.DependencyAnalysis
{
    public sealed class Ppc64leRuntimeImportMethodNode : ObjectNode, IMethodNode, ISymbolDefinitionNode
    {
        private const int StackFrameSize = 32;
        private const int LinkRegisterSaveOffset = 16;
        private const int TocSaveOffset = 24;

        private readonly MethodDesc _method;
        private readonly Utf8String _importName;

        public static bool ShouldUseThunk(MethodDesc method)
        {
            string importName = ((EcmaMethod)method).GetRuntimeImportName();
            return ShouldUseRuntimeImportThunk(importName);
        }

        private static bool ShouldUseRuntimeImportThunk(string symbolName)
        {
            return symbolName
                is "acos"
                or "acosf"
                or "acosh"
                or "acoshf"
                or "asin"
                or "asinf"
                or "asinh"
                or "asinhf"
                or "atan"
                or "atanf"
                or "atan2"
                or "atan2f"
                or "atanh"
                or "atanhf"
                or "ceil"
                or "ceilf"
                or "cos"
                or "cosf"
                or "cosh"
                or "coshf"
                or "floor"
                or "floorf"
                or "fmod"
                or "fmodf"
                or "memmove"
                or "memset"
                or "modf"
                or "modff"
                or "pow"
                or "powf"
                or "sin"
                or "sinf"
                or "sinh"
                or "sinhf"
                or "sqrt"
                or "sqrtf"
                or "tan"
                or "tanf"
                or "tanh"
                or "tanhf";
        }

        public Ppc64leRuntimeImportMethodNode(MethodDesc method, NameMangler nameMangler)
        {
            Debug.Assert(method.IsInternalCall);
            Debug.Assert(method.HasCustomAttribute("System.Runtime", "RuntimeImportAttribute"));

            _method = method;
            _importName = nameMangler.NodeMangler.ExternMethod(new Utf8String(((EcmaMethod)method).GetRuntimeImportName()), method);
        }

        public MethodDesc Method => _method;

        public override ObjectNodeSection GetSection(NodeFactory factory) => ObjectNodeSection.TextSection;

        public override bool StaticDependenciesAreComputed => true;

        public override bool IsShareable => false;

        public int Offset => 0;

        public void AppendMangledName(NameMangler nameMangler, Utf8StringBuilder sb)
        {
            sb.Append(nameMangler.GetMangledMethodName(_method));
        }

        public override ObjectData GetData(NodeFactory factory, bool relocsOnly = false)
        {
            Debug.Assert(factory.Target.Architecture == TargetArchitecture.Ppc64le);

            Ppc64leEmitter emitter = new Ppc64leEmitter(factory, relocsOnly);
            emitter.Builder.RequireInitialAlignment(factory.Target.MinimumFunctionAlignment);
            emitter.Builder.AddSymbol(this);

            // Preserve the managed return address and TOC while this thunk makes the
            // external ELFv2 call through a GOT-loaded function address.
            emitter.EmitMFLR(Register.R0);
            emitter.EmitSTD(Register.R0, Register.R1, LinkRegisterSaveOffset);
            emitter.EmitSTDU(Register.R1, Register.R1, -StackFrameSize);
            emitter.EmitSTD(Register.R2, Register.R1, TocSaveOffset);
            emitter.EmitCALLViaGot(factory.ExternFunctionSymbol(_importName));
            emitter.EmitLD(Register.R2, Register.R1, TocSaveOffset);
            emitter.EmitLD(Register.R1, Register.R1, 0);
            emitter.EmitLD(Register.R0, Register.R1, LinkRegisterSaveOffset);
            emitter.EmitMTLR(Register.R0);
            emitter.EmitRET();

            return emitter.Builder.ToObjectData();
        }

        protected override string GetName(NodeFactory factory) => this.GetMangledName(factory.NameMangler);

        public override int ClassCode => 2046663604;

        public override int CompareToImpl(ISortableNode other, CompilerComparer comparer)
        {
            return comparer.Compare(_method, ((Ppc64leRuntimeImportMethodNode)other)._method);
        }
    }
}
