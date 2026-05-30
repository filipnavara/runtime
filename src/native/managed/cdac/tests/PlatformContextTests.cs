// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Diagnostics.DataContractReader.Contracts.StackWalkHelpers;
using System.Runtime.InteropServices;
using Xunit;

namespace Microsoft.Diagnostics.DataContractReader.Tests;

public class PlatformContextTests
{
    [Theory]
    [InlineData(0, 0xAABBCCDD11223344UL)]
    [InlineData(4, 0x1234UL)] // Rsp
    [InlineData(15, 0xFFFFUL)] // R15
    public void AMD64_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new AMD64Context();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(16)]
    public void AMD64_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new AMD64Context();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Theory]
    [InlineData(0, 0x1234UL)]  // X0
    [InlineData(29, 0xABCDUL)] // Fp
    [InlineData(31, 0x5678UL)] // Sp
    [InlineData(32, 0x9000UL)] // Pc
    public void ARM64_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new ARM64Context();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(33)]
    public void ARM64_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new ARM64Context();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Theory]
    [InlineData(0, 0x12U)]   // R0
    [InlineData(13, 0x100U)] // Sp
    [InlineData(15, 0x40U)]  // Pc
    [InlineData(16, 0x10U)]  // Cpsr
    public void ARM_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new ARMContext();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(17)]
    public void ARM_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new ARMContext();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Theory]
    [InlineData(0, 0xDEADBEEFUL)] // Eax
    [InlineData(4, 0x1000UL)]     // Esp
    [InlineData(7, 0xABCDUL)]     // Edi
    public void X86_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new X86Context();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue & uint.MaxValue, result.Value); // X86 fields are uint
    }

    [Theory]
    [InlineData(8)]
    public void X86_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new X86Context();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Theory]
    [InlineData(0, 0x1234UL)]   // R0
    [InlineData(3, 0x2000UL)]   // Sp
    [InlineData(31, 0xABCDUL)]  // S8
    public void LoongArch64_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new LoongArch64Context();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(32)]
    public void LoongArch64_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new LoongArch64Context();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Theory]
    [InlineData(1, 0x1234UL)]  // Ra
    [InlineData(2, 0x2000UL)]  // Sp
    [InlineData(31, 0xABCDUL)] // T6
    public void RISCV64_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new RISCV64Context();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(32)]
    public void RISCV64_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new RISCV64Context();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Fact]
    public void RISCV64_ZeroRegister_ReadReturnsZero_WriteReturnsFalse()
    {
        var ctx = new RISCV64Context();
        Assert.True(ctx.TryReadRegister(0, out TargetNUInt value));
        Assert.Equal(0UL, value.Value);
        Assert.False(ctx.TrySetRegister(0, new TargetNUInt(0xDEAD)));
    }

    [Theory]
    [InlineData(0, 0x1234UL)]  // R0
    [InlineData(1, 0x2000UL)]  // R1/SP
    [InlineData(31, 0xABCDUL)] // R31/FP
    public void PPC64LE_TrySetAndRead_ByNumber_RoundTrips(int regNum, ulong testValue)
    {
        var ctx = new PPC64LEContext();
        Assert.True(ctx.TrySetRegister(regNum, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regNum, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(32)]
    public void PPC64LE_OutOfRange_ReturnsFalse(int regNum)
    {
        var ctx = new PPC64LEContext();
        Assert.False(ctx.TrySetRegister(regNum, new TargetNUInt(0)));
        Assert.False(ctx.TryReadRegister(regNum, out _));
    }

    [Theory]
    [InlineData("r3", 0x3333UL)]
    [InlineData("sp", 0x1000UL)]
    [InlineData("fp", 0x2000UL)]
    [InlineData("pc", 0x3000UL)]
    [InlineData("lr", 0x4000UL)]
    public void PPC64LE_TrySetAndRead_ByName_RoundTrips(string regName, ulong testValue)
    {
        var ctx = new PPC64LEContext();
        Assert.True(ctx.TrySetRegister(regName, new TargetNUInt(testValue)));
        Assert.True(ctx.TryReadRegister(regName, out TargetNUInt result));
        Assert.Equal(testValue, result.Value);
    }

    [Theory]
    [InlineData(nameof(PPC64LEContext.ContextFlags), 0x000)]
    [InlineData(nameof(PPC64LEContext.R0), 0x008)]
    [InlineData(nameof(PPC64LEContext.R31), 0x100)]
    [InlineData(nameof(PPC64LEContext.F0), 0x108)]
    [InlineData(nameof(PPC64LEContext.F31), 0x200)]
    [InlineData(nameof(PPC64LEContext.Fpscr), 0x208)]
    [InlineData(nameof(PPC64LEContext.Nip), 0x210)]
    [InlineData(nameof(PPC64LEContext.Link), 0x228)]
    [InlineData(nameof(PPC64LEContext.Xer), 0x230)]
    [InlineData(nameof(PPC64LEContext.Ccr), 0x234)]
    public void PPC64LE_ContextLayout_MatchesPalContext(string fieldName, int expectedOffset)
    {
        Assert.Equal(expectedOffset, Marshal.OffsetOf<PPC64LEContext>(fieldName).ToInt32());
    }

    [Fact]
    public void PPC64LE_ContextSize_MatchesPalContext()
    {
        var ctx = new PPC64LEContext();
        Assert.Equal(0x240u, ctx.Size);
        Assert.Equal(0x240, Marshal.SizeOf<PPC64LEContext>());
    }
}
