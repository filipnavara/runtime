// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using ILCompiler.DependencyAnalysis.Ppc64le;
using ILCompiler.DependencyAnalysisFramework;

using Internal.Text;
using Internal.TypeSystem;

using Debug = System.Diagnostics.Debug;

namespace ILCompiler.DependencyAnalysis
{
    internal sealed class Ppc64leUnmanagedCallersOnlyExportThunkNode : ObjectNode, ISymbolDefinitionNode
    {
        private readonly MethodDesc _method;
        private readonly IMethodNode _target;

        public Ppc64leUnmanagedCallersOnlyExportThunkNode(MethodDesc method, IMethodNode target)
        {
            Debug.Assert(method.IsUnmanagedCallersOnly);

            _method = method;
            _target = target;
        }

        public override ObjectNodeSection GetSection(NodeFactory factory) => ObjectNodeSection.TextSection;

        public override bool StaticDependenciesAreComputed => true;

        public override bool IsShareable => false;

        public int Offset => 0;

        public void AppendMangledName(NameMangler nameMangler, Utf8StringBuilder sb)
        {
            sb.Append("__ppc64le_reverse_pinvoke_export_thunk_"u8);
            sb.Append(nameMangler.GetMangledMethodName(_method));
        }

        public override ObjectData GetData(NodeFactory factory, bool relocsOnly = false)
        {
            Debug.Assert(factory.Target.Architecture == TargetArchitecture.Ppc64le);

            Ppc64leEmitter emitter = new Ppc64leEmitter(factory, relocsOnly);
            emitter.Builder.RequireInitialAlignment(factory.Target.MinimumFunctionAlignment);
            emitter.Builder.AddSymbol(this);

            emitter.EmitEstablishTocFromEntryPoint(this);
            emitter.EmitJMP(_target);

            return emitter.Builder.ToObjectData();
        }

        protected override string GetName(NodeFactory factory) => this.GetMangledName(factory.NameMangler);

        public override int ClassCode => -1602785301;

        public override int CompareToImpl(ISortableNode other, CompilerComparer comparer)
        {
            return comparer.Compare(_method, ((Ppc64leUnmanagedCallersOnlyExportThunkNode)other)._method);
        }
    }
}
