// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text;

namespace ILCompiler.Reflection.ReadyToRun.Ppc64le
{
    public class Epilog
    {
        public int Index { get; set; }

        public uint EpilogStartOffset { get; set; }
        public uint Res { get; set; }
        public uint EpilogStartIndex { get; set; }
        public uint EpilogStartOffsetFromMainFunctionBegin { get; set; }

        public Epilog() { }

        public Epilog(int index, int dw, uint startOffset)
        {
            Index = index;

            EpilogStartOffset = UnwindInfo.ExtractBits(dw, 0, 18);
            Res = UnwindInfo.ExtractBits(dw, 18, 4);
            EpilogStartIndex = UnwindInfo.ExtractBits(dw, 22, 10);

            // PPC64LE unwind function-length and epilog offsets are stored in two-byte units.
            EpilogStartOffsetFromMainFunctionBegin = EpilogStartOffset * 2 + startOffset;
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"        Epilog Start Offset: 0x{EpilogStartOffset:X5} Actual offset = 0x{EpilogStartOffset * 2:X5} Offset from main function begin = 0x{EpilogStartOffsetFromMainFunctionBegin:X6}");
            sb.Append($"        Epilog Start Index: {EpilogStartIndex} (0x{EpilogStartIndex:X})");
            return sb.ToString();
        }
    }

    /// <summary>
    /// Based on src/coreclr/jit/unwindppc64le.cpp DumpUnwindInfo.
    /// </summary>
    public class UnwindInfo : BaseUnwindInfo
    {
        public uint CodeWords { get; set; }
        public uint EpilogCount { get; set; }
        public uint EBit { get; set; }
        public uint XBit { get; set; }
        public uint Vers { get; set; }
        public uint FunctionLength { get; set; }

        public uint ExtendedCodeWords { get; set; }
        public uint ExtendedEpilogCount { get; set; }

        public Epilog[] Epilogs { get; set; }

        public UnwindInfo() { }

        public UnwindInfo(NativeReader imageReader, int offset)
        {
            uint startOffset = (uint)offset;

            int dw = imageReader.ReadInt32(ref offset);
            CodeWords = ExtractBits(dw, 27, 5);
            EpilogCount = ExtractBits(dw, 22, 5);
            EBit = ExtractBits(dw, 21, 1);
            XBit = ExtractBits(dw, 20, 1);
            Vers = ExtractBits(dw, 18, 2);
            FunctionLength = ExtractBits(dw, 0, 18) * 2;

            uint codeWords = CodeWords;
            uint epilogCount = EpilogCount;

            if (codeWords == 0 && epilogCount == 0)
            {
                dw = imageReader.ReadInt32(ref offset);
                ExtendedCodeWords = ExtractBits(dw, 16, 8);
                ExtendedEpilogCount = ExtractBits(dw, 0, 16);
                codeWords = ExtendedCodeWords;
                epilogCount = ExtendedEpilogCount;
            }

            if (EBit == 0)
            {
                Epilogs = new Epilog[epilogCount];
                for (int scope = 0; scope < epilogCount; scope++)
                {
                    dw = imageReader.ReadInt32(ref offset);
                    Epilogs[scope] = new Epilog(scope, dw, startOffset);
                }
            }
            else
            {
                Epilogs = new Epilog[0];
            }

            Size = offset - (int)startOffset + (int)codeWords * 4;
            int alignmentPad = ((Size + sizeof(int) - 1) & ~(sizeof(int) - 1)) - Size;
            Size += alignmentPad + sizeof(uint);
        }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"    CodeWords: {CodeWords}");
            sb.AppendLine($"    EpilogCount: {EpilogCount}");
            sb.AppendLine($"    EBit: {EBit}");
            sb.AppendLine($"    XBit: {XBit}");
            sb.AppendLine($"    Vers: {Vers}");
            sb.AppendLine($"    FunctionLength: {FunctionLength}");
            if (CodeWords == 0 && EpilogCount == 0)
            {
                sb.AppendLine("    ---- Extension word ----");
                sb.AppendLine($"    Extended Code Words: {ExtendedCodeWords}");
                sb.AppendLine($"    Extended Epilog Count: {ExtendedEpilogCount}");
            }
            if (Epilogs.Length == 0)
            {
                sb.AppendLine("    No epilogs");
            }
            else
            {
                for (int i = 0; i < Epilogs.Length; i++)
                {
                    sb.AppendLine("        -------------------------");
                    sb.AppendLine(Epilogs[i].ToString());
                    sb.AppendLine("        -------------------------");
                }
            }
            return sb.ToString();
        }

        internal static uint ExtractBits(int dw, int start, int length)
        {
            return (uint)((dw >> start) & ((1 << length) - 1));
        }
    }
}
