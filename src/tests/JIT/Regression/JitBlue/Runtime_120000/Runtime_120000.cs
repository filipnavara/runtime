// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using Xunit;

public class Runtime_120000
{
    private struct TwoLongs
    {
        public long First;
        public long Second;
    }

    private struct SplitStruct
    {
        public IntPtr Pointer;
        public int Value;
    }

    [Fact]
    public static int TestEntryPoint()
    {
        IntPtr pointer = new IntPtr(unchecked((long)0x1122334455667788));

        int result = Callee(
            1,
            new TwoLongs { First = 2, Second = 3 },
            new TwoLongs { First = 4, Second = 5 },
            new TwoLongs { First = 6, Second = 7 },
            new SplitStruct { Pointer = pointer, Value = 0x12345678 },
            new SplitStruct { Pointer = pointer, Value = 0x23456789 });

        return result == unchecked((int)0x3579be01) ? 100 : 101;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Callee(
        long arg0,
        TwoLongs arg1,
        TwoLongs arg2,
        TwoLongs arg3,
        SplitStruct split,
        SplitStruct stack)
    {
        return split.Value + stack.Value;
    }
}
