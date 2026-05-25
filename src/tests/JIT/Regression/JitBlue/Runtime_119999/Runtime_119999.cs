// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using Xunit;

public class Runtime_119999
{
    private struct TwoRefs
    {
        public object First;
        public object Second;
    }

    private struct FloatAndRef
    {
        public float First;
        public object Second;
    }

    [Fact]
    public static int TestEntryPoint()
    {
        object first = new object();
        object second = new object();

        TwoRefs twoRefs = ReturnTwoRefs(first, second);
        FloatAndRef mixed = ReturnFloatAndRef(second);

        GC.Collect();
        GC.KeepAlive(twoRefs);
        GC.KeepAlive(mixed);

        return ReferenceEquals(twoRefs.First, first) && ReferenceEquals(twoRefs.Second, second) &&
               (mixed.First == 42.0f) && ReferenceEquals(mixed.Second, second)
                   ? 100
                   : 101;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static TwoRefs ReturnTwoRefs(object first, object second)
    {
        return new TwoRefs { First = first, Second = second };
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static FloatAndRef ReturnFloatAndRef(object second)
    {
        return new FloatAndRef { First = 42.0f, Second = second };
    }
}
