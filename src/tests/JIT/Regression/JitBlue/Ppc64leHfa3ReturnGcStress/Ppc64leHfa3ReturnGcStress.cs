// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using Xunit;

public class Ppc64leHfa3ReturnGcStress
{
    private struct Hfa3
    {
        public double X;
        public double Y;
        public double Z;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static Hfa3 Callee(double x, double y, double z)
    {
        return new Hfa3 { X = x, Y = y, Z = z };
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static Hfa3 Wrapper(object gcRef, double x, double y, double z)
    {
        Hfa3 result = Callee(x, y, z);
        GC.KeepAlive(gcRef);
        return result;
    }

    [Fact]
    public static void TestEntryPoint()
    {
        object gcRef = new object();
        Hfa3 result = Wrapper(gcRef, 1.25, 2.5, 3.75);

        if ((result.X != 1.25) || (result.Y != 2.5) || (result.Z != 3.75))
        {
            throw new Exception($"Unexpected result: {result.X}, {result.Y}, {result.Z}");
        }
    }
}
