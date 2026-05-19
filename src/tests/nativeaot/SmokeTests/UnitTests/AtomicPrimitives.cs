// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Threading;

internal static class AtomicPrimitives
{
    private const int Pass = 100;

    private static int s_intValue;
    private static long s_longValue;
    private static object? s_objectValue;
    private static AtomicBox? s_genericObjectValue;

    public static int Run()
    {
        TestVolatileInt();
        TestVolatileObject();
        TestCompareExchangeInt();
        TestCompareExchangeLong();
        TestCompareExchangeObject();
        TestCompareExchangeGenericObject();

        return Pass;
    }

    private static void TestVolatileInt()
    {
        Volatile.Write(ref s_intValue, 42);
        AssertEquals(42, Volatile.Read(ref s_intValue));
    }

    private static void TestVolatileObject()
    {
        object expected = new object();
        Volatile.Write(ref s_objectValue, expected);
        AssertSame(expected, Volatile.Read(ref s_objectValue));
    }

    private static void TestCompareExchangeInt()
    {
        s_intValue = 0;
        AssertEquals(0, Interlocked.CompareExchange(ref s_intValue, 1, 0));
        AssertEquals(1, Volatile.Read(ref s_intValue));
        AssertEquals(1, Interlocked.CompareExchange(ref s_intValue, 2, 0));
        AssertEquals(1, Volatile.Read(ref s_intValue));
    }

    private static void TestCompareExchangeLong()
    {
        s_longValue = 0;
        AssertEquals(0, Interlocked.CompareExchange(ref s_longValue, 0x1234_5678_9abc_def0L, 0));
        AssertEquals(0x1234_5678_9abc_def0L, Volatile.Read(ref s_longValue));
        AssertEquals(0x1234_5678_9abc_def0L, Interlocked.CompareExchange(ref s_longValue, 2, 0));
        AssertEquals(0x1234_5678_9abc_def0L, Volatile.Read(ref s_longValue));
    }

    private static void TestCompareExchangeObject()
    {
        object first = new object();
        object second = new object();

        s_objectValue = null;
        AssertSame(null, Interlocked.CompareExchange(ref s_objectValue, first, null));
        AssertSame(first, Volatile.Read(ref s_objectValue));
        AssertSame(first, Interlocked.CompareExchange(ref s_objectValue, second, null));
        AssertSame(first, Volatile.Read(ref s_objectValue));
    }

    private static void TestCompareExchangeGenericObject()
    {
        AtomicBox first = new AtomicBox(1);
        AtomicBox second = new AtomicBox(2);

        s_genericObjectValue = null;
        AssertSame(null, GenericCompareExchange(ref s_genericObjectValue, first, null));
        AssertSame(first, Volatile.Read(ref s_genericObjectValue));
        AssertSame(first, GenericCompareExchange(ref s_genericObjectValue, second, null));
        AssertSame(first, Volatile.Read(ref s_genericObjectValue));
    }

    private static T? GenericCompareExchange<T>(ref T? location, T? value, T? comparand)
        where T : class
    {
        return Interlocked.CompareExchange(ref location, value, comparand);
    }

    private static void AssertEquals(int expected, int actual)
    {
        if (actual != expected)
            throw new Exception($"Expected {expected}, got {actual}");
    }

    private static void AssertEquals(long expected, long actual)
    {
        if (actual != expected)
            throw new Exception($"Expected {expected}, got {actual}");
    }

    private static void AssertSame(object? expected, object? actual)
    {
        if (!ReferenceEquals(expected, actual))
            throw new Exception("Expected identical object references");
    }

    private sealed class AtomicBox
    {
        public AtomicBox(int value)
        {
            Value = value;
        }

        public int Value { get; }
    }
}
