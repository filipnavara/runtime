// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Internal.TypeSystem;
using Internal.TypeSystem.Ecma;

using Debug = System.Diagnostics.Debug;

namespace ILCompiler
{
    public static class PseudoDescExtensions
    {
        public static PropertyPseudoDesc GetPropertyForAccessor(this MethodDesc accessor)
        {
            if (!accessor.IsSpecialName || accessor.GetTypicalMethodDefinition() is not EcmaMethod ecmaAccessor)
                return null;

            var property = ecmaAccessor.Module.GetPropertyForAccessor(ecmaAccessor.Handle);
            return property.IsNil ? null : new PropertyPseudoDesc(ecmaAccessor.OwningType, property);
        }

        public static EventPseudoDesc GetEventForAccessor(this MethodDesc accessor)
        {
            if (!accessor.IsSpecialName || accessor.GetTypicalMethodDefinition() is not EcmaMethod ecmaAccessor)
                return null;

            var @event = ecmaAccessor.Module.GetEventForAccessor(ecmaAccessor.Handle);
            return @event.IsNil ? null : new EventPseudoDesc(ecmaAccessor.OwningType, @event);
        }
    }
}
