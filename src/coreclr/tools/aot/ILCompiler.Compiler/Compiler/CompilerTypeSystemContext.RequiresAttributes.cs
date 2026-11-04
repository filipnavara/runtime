// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Reflection.Metadata;

using Internal.TypeSystem;
using Internal.TypeSystem.Ecma;

namespace ILCompiler
{
    public partial class CompilerTypeSystemContext
    {
        internal const string RequiresAttributeNamespace = "System.Diagnostics.CodeAnalysis";
        internal const string RequiresAttributeNamePrefix = "Requires";

        private sealed class RequiresAttributeParents
        {
            public readonly EcmaModule Module;
            public readonly HashSet<EntityHandle> Parents;

            public RequiresAttributeParents(EcmaModule module)
            {
                Module = module;
                Parents = new HashSet<EntityHandle>();

                MetadataReader reader = module.MetadataReader;
                foreach (CustomAttributeHandle attributeHandle in reader.CustomAttributes)
                {
                    if (reader.GetAttributeNamespaceAndName(attributeHandle, out StringHandle namespaceHandle, out StringHandle nameHandle)
                        && reader.StringComparer.Equals(namespaceHandle, RequiresAttributeNamespace)
                        && reader.StringComparer.StartsWith(nameHandle, RequiresAttributeNamePrefix))
                    {
                        Parents.Add(reader.GetCustomAttribute(attributeHandle).Parent);
                    }
                }
            }
        }

        private sealed class RequiresAttributeParentsHashtable : LockFreeReaderHashtable<EcmaModule, RequiresAttributeParents>
        {
            protected override int GetKeyHashCode(EcmaModule key) => key.GetHashCode();
            protected override int GetValueHashCode(RequiresAttributeParents value) => value.Module.GetHashCode();
            protected override bool CompareKeyToValue(EcmaModule key, RequiresAttributeParents value) => ReferenceEquals(key, value.Module);
            protected override bool CompareValueToValue(RequiresAttributeParents value1, RequiresAttributeParents value2) => ReferenceEquals(value1.Module, value2.Module);
            protected override RequiresAttributeParents CreateValueFromKey(EcmaModule key) => new RequiresAttributeParents(key);
        }

        private readonly RequiresAttributeParentsHashtable _requiresAttributeParents = new RequiresAttributeParentsHashtable();

        /// <summary>
        /// Returns false if the metadata entity has no custom attribute whose name starts with "Requires"
        /// in the System.Diagnostics.CodeAnalysis namespace. A return value of true means it might have one.
        /// </summary>
        public bool MayHaveRequiresAttribute(EcmaModule module, EntityHandle entity)
        {
            return _requiresAttributeParents.GetOrCreateValue(module).Parents.Contains(entity);
        }
    }
}
