// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Xunit;

namespace BigFrames_largeoffsets
{
    [StructLayout(LayoutKind.Explicit, Size = 70064)]
    public struct LargeRefFrame
    {
        [FieldOffset(0)]
        public object Head;

        [FieldOffset(65520)]
        public object Tail;
    }

    [StructLayout(LayoutKind.Explicit, Size = 70064)]
    public struct LargeUnalignedFrame
    {
        [FieldOffset(2)]
        public int LowInt;

        [FieldOffset(8)]
        public object Root;

        [FieldOffset(65534)]
        public int HighInt;
    }

    public sealed class Marker
    {
        public Marker(int value)
        {
            Value = value;
        }

        public int Value;
    }

    public class Test
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        private static Marker NewMarker(int value)
        {
            return new Marker(value);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void StoreRef(ref object slot, object value)
        {
            slot = value;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static object LoadRef(ref object slot)
        {
            return slot;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void ForceCollections()
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int ConsumeLargeRefFrame(
            int a0, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, LargeRefFrame frame)
        {
            ForceCollections();
            return ((Marker)frame.Head).Value + ((Marker)frame.Tail).Value + a0 + a9;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int LargeLocalRefStores()
        {
            LargeRefFrame frame = default;

            Marker head = NewMarker(17);
            Marker tail = NewMarker(23);

            frame.Head = head;
            StoreRef(ref frame.Tail, tail);

            head = null;
            tail = null;
            ForceCollections();

            return ((Marker)frame.Head).Value + ((Marker)LoadRef(ref frame.Tail)).Value;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int LargeOutgoingRefCopy()
        {
            LargeRefFrame frame = default;

            Marker head = NewMarker(31);
            Marker tail = NewMarker(37);

            StoreRef(ref frame.Head, head);
            frame.Tail = tail;

            head = null;
            tail = null;

            return ConsumeLargeRefFrame(3, 4, 5, 6, 7, 8, 9, 10, 11, 13, frame);
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static int LargeUnalignedSignedLoads()
        {
            LargeUnalignedFrame frame = default;

            Marker root = NewMarker(41);
            frame.LowInt = -1234567;
            frame.Root = root;
            frame.HighInt = -7654321;

            root = null;
            ForceCollections();

            return frame.LowInt + frame.HighInt + ((Marker)frame.Root).Value;
        }

        [Fact]
        [OuterLoop]
        public static int TestEntryPoint()
        {
            int result = LargeLocalRefStores();
            result += LargeOutgoingRefCopy();
            result += LargeUnalignedSignedLoads();

            const int expected = 17 + 23 + 31 + 37 + 3 + 13 - 1234567 - 7654321 + 41;
            if (result != expected)
            {
                Console.WriteLine($"Expected {expected}, got {result}");
                return 101;
            }

            return 100;
        }
    }
}
