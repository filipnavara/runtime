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

        public void EmitADDIS(Register regDst, Register regSrc, int offset)
        {
            Debug.Assert((uint)regDst <= 0x1f);
            Debug.Assert((uint)regSrc <= 0x1f);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));

            Builder.EmitUInt(0x3c000000u | ((uint)regDst << 21) | ((uint)regSrc << 16) | ((uint)offset & 0xffff));
        }

        public void EmitSUBF(Register regDst, Register regSubtrahend, Register regMinuend)
        {
            Debug.Assert((uint)regDst <= 0x1f);
            Debug.Assert((uint)regSubtrahend <= 0x1f);
            Debug.Assert((uint)regMinuend <= 0x1f);

            Builder.EmitUInt(0x7c000050u | ((uint)regDst << 21) | ((uint)regSubtrahend << 16) | ((uint)regMinuend << 11));
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
            EmitBNE(4 + GetJmpInstructionSize(symbol));
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

            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_TOC16_HA);
            EmitADDIS(regDst, Register.R2, 0);

            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_TOC16_LO);
            EmitADDI(regDst, regDst, 0);
        }

        public void EmitEstablishTocFromEntryPoint(ISymbolNode entryPoint)
        {
            const int pcAnchorOffset = 8;

            EmitMFLR(Register.R0);
            EmitBLNextInstruction();
            EmitMFLR(Register.R2);
            EmitMTLR(Register.R0);

            Builder.EmitReloc(entryPoint, RelocType.IMAGE_REL_BASED_PPC64_TOC16_HA);
            EmitADDIS(Register.R11, Register.R0, 0);

            Builder.EmitReloc(entryPoint, RelocType.IMAGE_REL_BASED_PPC64_TOC16_LO);
            EmitADDI(Register.R11, Register.R11, 0);

            EmitSUBF(Register.R2, Register.R11, Register.R2);
            EmitADDI(Register.R2, Register.R2, -pcAnchorOffset);
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

        private void EmitBLNextInstruction()
        {
            // bl .+4
            Builder.EmitUInt(0x48000005);
        }

        private void EmitBNE(int offset)
        {
            Debug.Assert((offset & 0x3) == 0);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));

            Builder.EmitUInt(0x40820000u | ((uint)offset & 0xfffc));
        }

        private static int GetJmpInstructionSize(ISymbolNode symbol)
        {
            if (!symbol.RepresentsIndirectionCell)
            {
                return 4;
            }

            return GetLoadSymbolInstructionSize() + 4 + 8;
        }

        private static int GetLoadSymbolInstructionSize()
        {
            return 8;
        }
    }
}
