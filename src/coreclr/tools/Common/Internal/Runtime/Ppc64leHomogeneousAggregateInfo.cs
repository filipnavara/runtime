// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using Internal.TypeSystem;
using static Internal.JitInterface.FpStruct;

namespace Internal.JitInterface
{
    public readonly struct Ppc64leHomogeneousAggregateInfo
    {
        private const int MaxElements = 8;

        public const int PosElementCount = 9;
        public const uint HomogeneousAggregate = 1u << 8;
        public const uint ElementCountMask = 0b1111u << PosElementCount;

        public readonly uint ElementSize;
        public readonly uint ElementCount;

        private Ppc64leHomogeneousAggregateInfo(uint elementSize, uint elementCount)
        {
            ElementSize = elementSize;
            ElementCount = elementCount;
        }

        public bool IsHomogeneousAggregate => ElementCount != 0;

        public uint EncodeAsFpReturnSize()
        {
            Debug.Assert(IsHomogeneousAggregate);
            return HomogeneousAggregate |
                (ElementCount << PosElementCount) |
                ((ElementSize == sizeof(double) ? 3u : 2u) << (int)PosSizeShift1st);
        }

        public static bool TryGet(TypeDesc td, out Ppc64leHomogeneousAggregateInfo info)
        {
            info = default;

            if (td is not DefType defType)
                return false;

            int elemSize = (defType.ValueTypeShapeCharacteristics & ValueTypeShapeCharacteristics.AggregateMask) switch
            {
                ValueTypeShapeCharacteristics.Float32Aggregate => sizeof(float),
                ValueTypeShapeCharacteristics.Float64Aggregate => sizeof(double),
                _ => 0
            };

            int size = td.GetElementSize().AsInt;
            if (elemSize == 0 || (size % elemSize) != 0)
                return false;

            int elemCount = size / elemSize;
            if (elemCount is < 1 or > MaxElements)
                return false;

            info = new Ppc64leHomogeneousAggregateInfo((uint)elemSize, (uint)elemCount);
            return true;
        }
    }
}
