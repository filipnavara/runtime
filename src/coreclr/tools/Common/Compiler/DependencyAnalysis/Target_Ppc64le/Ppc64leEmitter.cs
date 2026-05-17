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
            throw new NotImplementedException("PPC64LE symbol address materialization is not implemented");
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
            throw new NotImplementedException("PPC64LE symbol load is not implemented");
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
                throw new NotImplementedException("PPC64LE indirect symbol jump is not implemented");
            }

            Builder.EmitReloc(symbol, RelocType.IMAGE_REL_BASED_PPC64_REL24);
            // b symbol
            Builder.EmitUInt(0x48000000);
        }

        public void EmitNOP()
        {
            Builder.EmitUInt(0x60000000);
        }
    }
}
