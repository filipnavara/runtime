// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;
using Microsoft.Diagnostics.DataContractReader.Contracts.StackWalkHelpers.PPC64LE;

namespace Microsoft.Diagnostics.DataContractReader.Contracts.StackWalkHelpers;

/// <summary>
/// PPC64LE-specific thread context.
/// </summary>
[StructLayout(LayoutKind.Explicit, Pack = 1, Size = 0x240)]
internal struct PPC64LEContext : IPlatformContext
{
    [Flags]
    public enum ContextFlagsValues : uint
    {
        CONTEXT_PPC64 = 0x100000,
        CONTEXT_CONTROL = CONTEXT_PPC64 | 0x1,
        CONTEXT_INTEGER = CONTEXT_PPC64 | 0x2,
        CONTEXT_FLOATING_POINT = CONTEXT_PPC64 | 0x4,
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT,
        CONTEXT_ALL = CONTEXT_FULL,
        CONTEXT_UNWOUND_TO_CALL = 0x20000000,
        CONTEXT_AREA_MASK = 0xFFFF,
    }

    public readonly uint Size => 0x240;

    public readonly uint ContextControlFlags => (uint)ContextFlagsValues.CONTEXT_CONTROL;

    public readonly uint FullContextFlags => (uint)ContextFlagsValues.CONTEXT_FULL;

    public readonly uint AllContextFlags => (uint)ContextFlagsValues.CONTEXT_ALL;

    public readonly int StackPointerRegister => 1;

    public TargetPointer StackPointer
    {
        readonly get => new(R1);
        set => R1 = value.Value;
    }

    public TargetPointer InstructionPointer
    {
        readonly get => new(Nip);
        set => Nip = value.Value;
    }

    public TargetPointer FramePointer
    {
        readonly get => new(R31);
        set => R31 = value.Value;
    }

    public uint RawContextFlags { readonly get => ContextFlags; set => ContextFlags = value; }

    public void Unwind(Target target)
    {
        PPC64LEUnwinder unwinder = new(target);
        unwinder.Unwind(ref this);
    }

    public bool TrySetRegister(string name, TargetNUInt value)
    {
        if (TryGetRegisterNumber(name, out int number))
        {
            return TrySetRegister(number, value);
        }

        if (name.Equals("pc", StringComparison.OrdinalIgnoreCase) || name.Equals("nip", StringComparison.OrdinalIgnoreCase)) { Nip = value.Value; return true; }
        if (name.Equals("lr", StringComparison.OrdinalIgnoreCase) || name.Equals("link", StringComparison.OrdinalIgnoreCase)) { Link = value.Value; return true; }
        if (name.Equals("ctr", StringComparison.OrdinalIgnoreCase)) { Ctr = value.Value; return true; }
        if (name.Equals("xer", StringComparison.OrdinalIgnoreCase)) { Xer = (uint)value.Value; return true; }
        if (name.Equals("ccr", StringComparison.OrdinalIgnoreCase)) { Ccr = (uint)value.Value; return true; }
        return false;
    }

    public bool TryReadRegister(string name, out TargetNUInt value)
    {
        if (TryGetRegisterNumber(name, out int number))
        {
            return TryReadRegister(number, out value);
        }

        if (name.Equals("pc", StringComparison.OrdinalIgnoreCase) || name.Equals("nip", StringComparison.OrdinalIgnoreCase)) { value = new TargetNUInt(Nip); return true; }
        if (name.Equals("lr", StringComparison.OrdinalIgnoreCase) || name.Equals("link", StringComparison.OrdinalIgnoreCase)) { value = new TargetNUInt(Link); return true; }
        if (name.Equals("ctr", StringComparison.OrdinalIgnoreCase)) { value = new TargetNUInt(Ctr); return true; }
        if (name.Equals("xer", StringComparison.OrdinalIgnoreCase)) { value = new TargetNUInt(Xer); return true; }
        if (name.Equals("ccr", StringComparison.OrdinalIgnoreCase)) { value = new TargetNUInt(Ccr); return true; }

        value = default;
        return false;
    }

    public bool TrySetRegister(int number, TargetNUInt value)
    {
        switch (number)
        {
            case 0: R0 = value.Value; return true;
            case 1: R1 = value.Value; return true;
            case 2: R2 = value.Value; return true;
            case 3: R3 = value.Value; return true;
            case 4: R4 = value.Value; return true;
            case 5: R5 = value.Value; return true;
            case 6: R6 = value.Value; return true;
            case 7: R7 = value.Value; return true;
            case 8: R8 = value.Value; return true;
            case 9: R9 = value.Value; return true;
            case 10: R10 = value.Value; return true;
            case 11: R11 = value.Value; return true;
            case 12: R12 = value.Value; return true;
            case 13: R13 = value.Value; return true;
            case 14: R14 = value.Value; return true;
            case 15: R15 = value.Value; return true;
            case 16: R16 = value.Value; return true;
            case 17: R17 = value.Value; return true;
            case 18: R18 = value.Value; return true;
            case 19: R19 = value.Value; return true;
            case 20: R20 = value.Value; return true;
            case 21: R21 = value.Value; return true;
            case 22: R22 = value.Value; return true;
            case 23: R23 = value.Value; return true;
            case 24: R24 = value.Value; return true;
            case 25: R25 = value.Value; return true;
            case 26: R26 = value.Value; return true;
            case 27: R27 = value.Value; return true;
            case 28: R28 = value.Value; return true;
            case 29: R29 = value.Value; return true;
            case 30: R30 = value.Value; return true;
            case 31: R31 = value.Value; return true;
            default: return false;
        }
    }

    public bool TryReadRegister(int number, out TargetNUInt value)
    {
        switch (number)
        {
            case 0: value = new TargetNUInt(R0); return true;
            case 1: value = new TargetNUInt(R1); return true;
            case 2: value = new TargetNUInt(R2); return true;
            case 3: value = new TargetNUInt(R3); return true;
            case 4: value = new TargetNUInt(R4); return true;
            case 5: value = new TargetNUInt(R5); return true;
            case 6: value = new TargetNUInt(R6); return true;
            case 7: value = new TargetNUInt(R7); return true;
            case 8: value = new TargetNUInt(R8); return true;
            case 9: value = new TargetNUInt(R9); return true;
            case 10: value = new TargetNUInt(R10); return true;
            case 11: value = new TargetNUInt(R11); return true;
            case 12: value = new TargetNUInt(R12); return true;
            case 13: value = new TargetNUInt(R13); return true;
            case 14: value = new TargetNUInt(R14); return true;
            case 15: value = new TargetNUInt(R15); return true;
            case 16: value = new TargetNUInt(R16); return true;
            case 17: value = new TargetNUInt(R17); return true;
            case 18: value = new TargetNUInt(R18); return true;
            case 19: value = new TargetNUInt(R19); return true;
            case 20: value = new TargetNUInt(R20); return true;
            case 21: value = new TargetNUInt(R21); return true;
            case 22: value = new TargetNUInt(R22); return true;
            case 23: value = new TargetNUInt(R23); return true;
            case 24: value = new TargetNUInt(R24); return true;
            case 25: value = new TargetNUInt(R25); return true;
            case 26: value = new TargetNUInt(R26); return true;
            case 27: value = new TargetNUInt(R27); return true;
            case 28: value = new TargetNUInt(R28); return true;
            case 29: value = new TargetNUInt(R29); return true;
            case 30: value = new TargetNUInt(R30); return true;
            case 31: value = new TargetNUInt(R31); return true;
            default: value = default; return false;
        }
    }

    private static bool TryGetRegisterNumber(string name, out int number)
    {
        number = -1;

        if (name.Equals("sp", StringComparison.OrdinalIgnoreCase))
        {
            number = 1;
            return true;
        }

        if (name.Equals("fp", StringComparison.OrdinalIgnoreCase))
        {
            number = 31;
            return true;
        }

        if ((name.Length < 2) || (char.ToLowerInvariant(name[0]) != 'r'))
        {
            return false;
        }

        if (int.TryParse(name.AsSpan(1), out number) && (number >= 0) && (number <= 31))
        {
            return true;
        }

        number = -1;
        return false;
    }

    [FieldOffset(0x0)]
    public uint ContextFlags;

    [Register(RegisterType.General)]
    [FieldOffset(0x008)] public ulong R0;
    [Register(RegisterType.General | RegisterType.StackPointer)]
    [FieldOffset(0x010)] public ulong R1;
    [Register(RegisterType.General)]
    [FieldOffset(0x018)] public ulong R2;
    [Register(RegisterType.General)]
    [FieldOffset(0x020)] public ulong R3;
    [Register(RegisterType.General)]
    [FieldOffset(0x028)] public ulong R4;
    [Register(RegisterType.General)]
    [FieldOffset(0x030)] public ulong R5;
    [Register(RegisterType.General)]
    [FieldOffset(0x038)] public ulong R6;
    [Register(RegisterType.General)]
    [FieldOffset(0x040)] public ulong R7;
    [Register(RegisterType.General)]
    [FieldOffset(0x048)] public ulong R8;
    [Register(RegisterType.General)]
    [FieldOffset(0x050)] public ulong R9;
    [Register(RegisterType.General)]
    [FieldOffset(0x058)] public ulong R10;
    [Register(RegisterType.General)]
    [FieldOffset(0x060)] public ulong R11;
    [Register(RegisterType.General)]
    [FieldOffset(0x068)] public ulong R12;
    [Register(RegisterType.General)]
    [FieldOffset(0x070)] public ulong R13;
    [Register(RegisterType.General)]
    [FieldOffset(0x078)] public ulong R14;
    [Register(RegisterType.General)]
    [FieldOffset(0x080)] public ulong R15;
    [Register(RegisterType.General)]
    [FieldOffset(0x088)] public ulong R16;
    [Register(RegisterType.General)]
    [FieldOffset(0x090)] public ulong R17;
    [Register(RegisterType.General)]
    [FieldOffset(0x098)] public ulong R18;
    [Register(RegisterType.General)]
    [FieldOffset(0x0a0)] public ulong R19;
    [Register(RegisterType.General)]
    [FieldOffset(0x0a8)] public ulong R20;
    [Register(RegisterType.General)]
    [FieldOffset(0x0b0)] public ulong R21;
    [Register(RegisterType.General)]
    [FieldOffset(0x0b8)] public ulong R22;
    [Register(RegisterType.General)]
    [FieldOffset(0x0c0)] public ulong R23;
    [Register(RegisterType.General)]
    [FieldOffset(0x0c8)] public ulong R24;
    [Register(RegisterType.General)]
    [FieldOffset(0x0d0)] public ulong R25;
    [Register(RegisterType.General)]
    [FieldOffset(0x0d8)] public ulong R26;
    [Register(RegisterType.General)]
    [FieldOffset(0x0e0)] public ulong R27;
    [Register(RegisterType.General)]
    [FieldOffset(0x0e8)] public ulong R28;
    [Register(RegisterType.General)]
    [FieldOffset(0x0f0)] public ulong R29;
    [Register(RegisterType.General)]
    [FieldOffset(0x0f8)] public ulong R30;
    [Register(RegisterType.General | RegisterType.FramePointer)]
    [FieldOffset(0x100)] public ulong R31;

    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x108)] public ulong F0;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x110)] public ulong F1;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x118)] public ulong F2;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x120)] public ulong F3;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x128)] public ulong F4;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x130)] public ulong F5;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x138)] public ulong F6;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x140)] public ulong F7;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x148)] public ulong F8;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x150)] public ulong F9;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x158)] public ulong F10;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x160)] public ulong F11;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x168)] public ulong F12;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x170)] public ulong F13;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x178)] public ulong F14;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x180)] public ulong F15;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x188)] public ulong F16;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x190)] public ulong F17;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x198)] public ulong F18;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1a0)] public ulong F19;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1a8)] public ulong F20;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1b0)] public ulong F21;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1b8)] public ulong F22;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1c0)] public ulong F23;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1c8)] public ulong F24;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1d0)] public ulong F25;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1d8)] public ulong F26;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1e0)] public ulong F27;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1e8)] public ulong F28;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1f0)] public ulong F29;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x1f8)] public ulong F30;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x200)] public ulong F31;
    [Register(RegisterType.FloatingPoint)]
    [FieldOffset(0x208)] public ulong Fpscr;

    [Register(RegisterType.Control | RegisterType.ProgramCounter)]
    [FieldOffset(0x210)] public ulong Nip;
    [Register(RegisterType.Control)]
    [FieldOffset(0x218)] public ulong Msr;
    [Register(RegisterType.Control)]
    [FieldOffset(0x220)] public ulong Ctr;
    [Register(RegisterType.Control)]
    [FieldOffset(0x228)] public ulong Link;
    [Register(RegisterType.Control)]
    [FieldOffset(0x230)] public uint Xer;
    [Register(RegisterType.Control)]
    [FieldOffset(0x234)] public uint Ccr;
}
