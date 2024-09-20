// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Java.Interop;

class Program
{
    static int Main(string[] args)
    { 
        var cycle1a = new JavaObject("cycle1a");
        var cycle1b = new JavaObject("cycle1b");
        var zig1a = new JavaObject("zig1a");
        var zig1b = new JavaObject("zig1b");
        cycle1a.Ref = cycle1b;
        cycle1b.Ref = cycle1a;
        zig1a.Ref = new object [] { zig1b };
        cycle1a = null;
        cycle1b = null;
        zig1a = null;
        zig1b = null;
        Console.WriteLine("Calling GC.Collect");
        GC.Collect();
        Console.WriteLine("Calling GC.WaitForPendingFinalizers");
        GC.WaitForPendingFinalizers();
        Console.WriteLine("Calling GC.Collect (2)");
        GC.Collect();
        Console.WriteLine("Calling GC.WaitForPendingFinalizers (2)");
        GC.WaitForPendingFinalizers();
        return 100;
    }    
}

namespace Java.Interop
{
    public class JavaObject
    {
        string name;
        public object Ref;

        public JavaObject(string name)
        {
            this.name = name;

            // NOTE: The real interop would save the handle and use it for object lookup dictionary
            _ = System.Runtime.InteropServices.Java.JavaBridge.CreateReferenceTrackingHandle(this);
        }

        ~JavaObject()
        {
            Console.WriteLine($"Finalizing {name}");
        }
    }
}

namespace System.Runtime.InteropServices.Java
{
   internal class JavaBridge
    {     
        public static GCHandle CreateReferenceTrackingHandle(object o)
        {
            // TODO: Check this is bridged object
            return GCHandle.FromIntPtr(RhHandleAllocRefCounted(o));
        }

        [MethodImpl(MethodImplOptions.InternalCall)]
        [RuntimeImport("*", "RhpHandleAlloc")]
        private static extern IntPtr RhpHandleAlloc(object value, GCHandleType type);

        //[LibraryImport(RuntimeHelpers.QCall, EntryPoint = "RhRegisterCrossReferencesCallback")]
        //private static partial unsafe void RhRegisterCrossReferencesCallback(delegate* unmanaged<int, IntPtr, int, IntPtr, void> crossReferencesCallback);

        internal static IntPtr RhHandleAllocRefCounted(object value)
        {
            const int HNDTYPE_REFCOUNTED = 5;
            return RhpHandleAlloc(value, (GCHandleType)HNDTYPE_REFCOUNTED);
        }
    }
}

namespace System.Runtime
{
    [AttributeUsage(AttributeTargets.Method | AttributeTargets.Constructor, Inherited = false)]
    internal sealed class RuntimeImportAttribute : Attribute
    {
        public string DllName { get; }
        public string EntryPoint { get; }

        public RuntimeImportAttribute(string entry)
        {
            EntryPoint = entry;
        }

        public RuntimeImportAttribute(string dllName, string entry)
        {
            EntryPoint = entry;
            DllName = dllName;
        }
    }
}
