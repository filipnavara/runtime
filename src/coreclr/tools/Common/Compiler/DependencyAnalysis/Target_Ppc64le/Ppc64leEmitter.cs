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
            _usePcRelativeAddressLoads = factory.UsePpc64lePcRelativeAddressLoads;
        }

        public ObjectDataBuilder Builder;
        public TargetRegisterMap TargetRegister;
        private readonly bool _usePcRelativeAddressLoads;

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

        public void EmitLDFromGot(Register regDst, ISymbolNode symbol)
        {
            Debug.Assert(regDst != Register.R0);

            if (_usePcRelativeAddressLoads)
            {
                throw new InvalidOperationException("PPC64LE ReadyToRun code must not use GOT-based address loads");
            }

            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_GOT16);
            EmitADDIS(regDst, Register.R2, 0);

            EmitLD(regDst, regDst, 0);
        }

        public void EmitSTD(Register regSrc, Register regDst, int offset)
        {
            Debug.Assert((uint)regSrc <= 0x1f);
            Debug.Assert((uint)regDst <= 0x1f);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));
            Debug.Assert((offset & 0x3) == 0);

            Builder.EmitUInt(0xf8000000u | ((uint)regSrc << 21) | ((uint)regDst << 16) | ((uint)offset & 0xfffc));
        }

        public void EmitSTDU(Register regSrc, Register regDst, int offset)
        {
            Debug.Assert((uint)regSrc <= 0x1f);
            Debug.Assert((uint)regDst <= 0x1f);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));
            Debug.Assert((offset & 0x3) == 0);

            Builder.EmitUInt(0xf8000001u | ((uint)regSrc << 21) | ((uint)regDst << 16) | ((uint)offset & 0xfffc));
        }

        public void EmitRET()
        {
            // blr
            Builder.EmitUInt(0x4e800020);
        }

        public void EmitJMP(Register reg)
        {
            // mtctr reg; bctr
            EmitMTCTR(reg);
            EmitBCTR();
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

        public void EmitLoadTargetAndSetCTR(ISymbolNode symbol)
        {
            if (symbol.RepresentsIndirectionCell)
            {
                EmitLD(Register.R12, symbol);
            }
            else
            {
                EmitMOV(Register.R12, symbol);
            }

            EmitMTCTR(Register.R12);
        }

        public void EmitCALL(ISymbolNode symbol)
        {
            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_REL24);
            // bl symbol
            Builder.EmitUInt(0x48000001);
            // Reserved for the linker to rewrite into a TOC restore if the target needs a PLT stub.
            EmitNOP();
        }

        public void EmitCALLViaGot(ISymbolNode symbol)
        {
            EmitLDFromGot(Register.R12, symbol);
            Builder.EmitUInt(0x7c0903a6u | ((uint)Register.R12 << 21));
            // bctrl
            Builder.EmitUInt(0x4e800421);
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

            if (_usePcRelativeAddressLoads)
            {
                // Preserve LR because these stubs may return to their caller after
                // materializing the address.
                EmitMFLR(Register.R0);
                EmitBranchAndLinkToNext();
                EmitMFLR(regDst);

                Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_REL16);
                EmitADDIS(regDst, regDst, 0);
                EmitADDI(regDst, regDst, 4);

                EmitMTLR(Register.R0);
                return;
            }

            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_TOC16);
            EmitADDIS(regDst, Register.R2, 0);

            EmitADDI(regDst, regDst, 0);
        }

        private void EmitBranchAndLinkToNext()
        {
            // bc BO=20, BI=31, BD=4, LK=1: branch-and-link to the next instruction.
            Builder.EmitUInt(0x429f0005);
        }

        public void EmitMFLR(Register regDst)
        {
            Debug.Assert((uint)regDst <= 0x1f);
            Builder.EmitUInt(0x7c0802a6u | ((uint)regDst << 21));
        }

        public void EmitMTLR(Register regSrc)
        {
            Debug.Assert((uint)regSrc <= 0x1f);
            Builder.EmitUInt(0x7c0803a6u | ((uint)regSrc << 21));
        }

        public void EmitMTCTR(Register regSrc)
        {
            Debug.Assert((uint)regSrc <= 0x1f);
            Builder.EmitUInt(0x7c0903a6u | ((uint)regSrc << 21));
        }

        public void EmitBCTR()
        {
            Builder.EmitUInt(0x4e800420);
        }

        private void EmitBNE(int offset)
        {
            Debug.Assert((offset & 0x3) == 0);
            Debug.Assert((offset >= short.MinValue) && (offset <= short.MaxValue));

            Builder.EmitUInt(0x40820000u | ((uint)offset & 0xfffc));
        }

        private int GetJmpInstructionSize(ISymbolNode symbol)
        {
            if (!symbol.RepresentsIndirectionCell)
            {
                return 4;
            }

            return GetLoadSymbolInstructionSize() + 4 + 8;
        }

        private int GetLoadSymbolInstructionSize()
        {
            return _usePcRelativeAddressLoads ? 24 : 8;
        }
    }
}
