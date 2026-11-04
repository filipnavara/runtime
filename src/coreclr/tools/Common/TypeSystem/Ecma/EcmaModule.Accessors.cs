// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Reflection.Metadata;
using System.Threading;

namespace Internal.TypeSystem.Ecma
{
    // Pluggable file that adds lookups from accessor methods to the properties and events that own them
    public partial class EcmaModule
    {
        private sealed class AccessorOwners
        {
            public readonly Dictionary<MethodDefinitionHandle, PropertyDefinitionHandle> Properties = new();
            public readonly Dictionary<MethodDefinitionHandle, EventDefinitionHandle> Events = new();
        }

        private AccessorOwners _accessorOwners;

        /// <summary>
        /// Returns the property that has <paramref name="accessor"/> as its getter or setter, or a nil handle
        /// if there's none. Only properties declared on the same type as the accessor are considered.
        /// </summary>
        public PropertyDefinitionHandle GetPropertyForAccessor(MethodDefinitionHandle accessor)
        {
            return GetAccessorOwners().Properties.TryGetValue(accessor, out PropertyDefinitionHandle property) ? property : default;
        }

        /// <summary>
        /// Returns the event that has <paramref name="accessor"/> as its adder, remover or raiser, or a nil handle
        /// if there's none. Only events declared on the same type as the accessor are considered.
        /// </summary>
        public EventDefinitionHandle GetEventForAccessor(MethodDefinitionHandle accessor)
        {
            return GetAccessorOwners().Events.TryGetValue(accessor, out EventDefinitionHandle @event) ? @event : default;
        }

        private AccessorOwners GetAccessorOwners()
        {
            return _accessorOwners ?? InitializeAccessorOwners();
        }

        private AccessorOwners InitializeAccessorOwners()
        {
            // The MethodSemantics table is sorted by the owning property/event, so finding the owner of
            // a given accessor would require walking all the properties/events of its declaring type.
            // Build a reverse map for the whole module instead.
            MetadataReader reader = MetadataReader;
            var owners = new AccessorOwners();

            foreach (TypeDefinitionHandle typeHandle in reader.TypeDefinitions)
            {
                TypeDefinition type = reader.GetTypeDefinition(typeHandle);

                foreach (PropertyDefinitionHandle propertyHandle in type.GetProperties())
                {
                    PropertyAccessors accessors = reader.GetPropertyDefinition(propertyHandle).GetAccessors();
                    Add(owners.Properties, accessors.Getter, propertyHandle);
                    Add(owners.Properties, accessors.Setter, propertyHandle);
                }

                foreach (EventDefinitionHandle eventHandle in type.GetEvents())
                {
                    EventAccessors accessors = reader.GetEventDefinition(eventHandle).GetAccessors();
                    Add(owners.Events, accessors.Adder, eventHandle);
                    Add(owners.Events, accessors.Remover, eventHandle);
                    Add(owners.Events, accessors.Raiser, eventHandle);
                }

                // Only accessors declared on the same type as the property/event count, and the first
                // property/event in declaration order wins.
                void Add<T>(Dictionary<MethodDefinitionHandle, T> map, MethodDefinitionHandle accessor, T owner)
                {
                    if (!accessor.IsNil && reader.GetMethodDefinition(accessor).GetDeclaringType() == typeHandle)
                        map.TryAdd(accessor, owner);
                }
            }

            Interlocked.CompareExchange(ref _accessorOwners, owners, null);
            return _accessorOwners;
        }
    }
}
