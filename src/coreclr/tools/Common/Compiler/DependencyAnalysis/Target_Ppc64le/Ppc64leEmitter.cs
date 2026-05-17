// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;

namespace ILCompiler.DependencyAnalysis.Ppc64le
{
    public struct Ppc64leEmitter
    {
        public Ppc64leEmitter(NodeFactory factory, bool relocsOnly)
        {
            Builder = new ObjectDataBuilder(factory, relocsOnly);
            TargetRegister = new TargetRegisterMap(factory.Target.OperatingSystem);
        }

        public ObjectDataBuilder Builder;
        public TargetRegisterMap TargetRegister;

        // Assembly stub creation api. TBD, actually make this general purpose.

        public void EmitBreak()
        {
            // trap
            Builder.EmitUInt(0x7fe00008);
        }

        public void EmitLI(Register regDst, int value)
        {
            EmitADDI(regDst, Register.R0, value);
        }

        public void EmitADDI(Register regDst, Register regSrc, int offset)
        {
            Debug.Assert((uint)regDst <= 0x1f);
            Debug.Assert((uint)regSrc <= 0x1f);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));

            Builder.EmitUInt(0x38000000u | ((uint)regDst << 21) | ((uint)regSrc << 16) | ((uint)offset & 0xffff));
        }

        public void EmitMOV(Register regDst, Register regSrc)
        {
            Debug.Assert(regSrc != Register.R0);
            EmitADDI(regDst, regSrc, 0);
        }

        public void EmitMOV(Register regDst, ISymbolNode symbol)
        {
            EmitLoadAddressFromLiteral(regDst, symbol);
        }

        public void EmitLD(Register regDst, Register regSrc, int offset)
        {
            Debug.Assert((uint)regDst <= 0x1f);
            Debug.Assert((uint)regSrc <= 0x1f);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));
            Debug.Assert((offset & 0x3) == 0);

            Builder.EmitUInt(0xe8000000u | ((uint)regDst << 21) | ((uint)regSrc << 16) | ((uint)offset & 0xfffc));
        }

        public void EmitLD(Register regDst, ISymbolNode symbol)
        {
            EmitMOV(regDst, symbol);
            EmitLD(regDst, regDst, 0);
        }

        public void EmitRET()
        {
            // blr
            Builder.EmitUInt(0x4e800020);
        }

        public void EmitJMP(Register reg)
        {
            // mtctr reg; bctr
            Builder.EmitUInt(0x7c0903a6u | ((uint)reg << 21));
            Builder.EmitUInt(0x4e800420);
        }

        public void EmitJMP(ISymbolNode symbol)
        {
            if (symbol.RepresentsIndirectionCell)
            {
                EmitLD(Register.R12, symbol);
                EmitJMP(Register.R12);
                return;
            }

            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_REL24);
            // b symbol
            Builder.EmitUInt(0x48000000);
        }

        public void EmitCMPDI(Register regSrc, int value)
        {
            Debug.Assert((uint)regSrc <= 0x1f);
            Debug.Assert((value >= short.MinValue) && (value <= short.MaxValue));

            Builder.EmitUInt(0x2c200000u | ((uint)regSrc << 16) | ((uint)value & 0xffff));
        }

        public void EmitJMPIfZero(Register regSrc, ISymbolNode symbol)
        {
            EmitCMPDI(regSrc, 0);
            EmitBNE(4 + GetJmpInstructionSize(symbol, Builder.CountBytes + 4));
            EmitJMP(symbol);
        }

        public void EmitRETIfZero(Register regSrc)
        {
            EmitCMPDI(regSrc, 0);
            EmitBNE(8);
            EmitRET();
        }

        public void EmitLWSYNC()
        {
            Builder.EmitUInt(0x7c2004ac);
        }

        public void EmitNOP()
        {
            Builder.EmitUInt(0x60000000);
        }

        private void EmitLoadAddressFromLiteral(Register regDst, ISymbolNode symbol)
        {
            Debug.Assert(regDst != Register.R0);

            Builder.RequireInitialPointerAlignment();

            if (((Builder.CountBytes + 24) & 7) != 0)
            {
                EmitNOP();
            }

            // Load a nearby absolute pointer literal through LR, while preserving
            // the caller's LR for the tail-called target.
            EmitMFLR(Register.R0);

            // bcl 20, 31, .+4
            Builder.EmitUInt(0x429f0005);
            EmitMFLR(regDst);
            EmitMTLR(Register.R0);

            EmitLD(regDst, regDst, 16);

            // b .+12
            Builder.EmitUInt(0x4800000c);
            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_DIR64);
        }

        private void EmitMFLR(Register regDst)
        {
            Debug.Assert((uint)regDst <= 0x1f);
            Builder.EmitUInt(0x7c0802a6u | ((uint)regDst << 21));
        }

        private void EmitMTLR(Register regSrc)
        {
            Debug.Assert((uint)regSrc <= 0x1f);
            Builder.EmitUInt(0x7c0803a6u | ((uint)regSrc << 21));
        }

        private void EmitBNE(int offset)
        {
            Debug.Assert((offset & 0x3) == 0);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));

            Builder.EmitUInt(0x40820000u | ((uint)offset & 0xfffc));
        }

        private static int GetJmpInstructionSize(ISymbolNode symbol, int startOffset)
        {
            if (!symbol.RepresentsIndirectionCell)
            {
                return 4;
            }

            return GetLoadSymbolInstructionSize(startOffset) + 4 + 8;
        }

        private static int GetLoadSymbolInstructionSize(int startOffset)
        {
            return 32 + ((((startOffset + 24) & 7) != 0) ? 4 : 0);
        }
    }
}
