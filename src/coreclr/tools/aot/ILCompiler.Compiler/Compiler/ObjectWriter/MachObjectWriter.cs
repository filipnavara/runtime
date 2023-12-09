// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using ILCompiler.DependencyAnalysis;
using ILCompiler.DependencyAnalysisFramework;
using Internal.TypeSystem;

namespace ILCompiler.ObjectWriter
{
    internal sealed class MachObjectWriter : UnixObjectWriter
    {
        private sealed record CompactUnwindCode(string PcStartSymbolName, uint PcLength, uint Code, string LsdaSymbolName = null, string PersonalitySymbolName = null);

        private readonly TargetOS _targetOS;
        private readonly MachCpuType _cpuType;
        private readonly List<MachSection> _sections = new();

        // Exception handling sections
        private MachSection _compactUnwindSection;
        private MemoryStream _compactUnwindStream;
        private readonly List<CompactUnwindCode> _compactUnwindCodes = new();
        private readonly uint _compactUnwindDwarfCode;

        // Symbol table
        private readonly Dictionary<string, uint> _symbolNameToIndex = new();
        private readonly List<MachSymbol> _symbolTable = new();
        private readonly MachDynamicLinkEditSymbolTable _dySymbolTable = new();

        public MachObjectWriter(NodeFactory factory, ObjectWritingOptions options)
            : base(factory, options)
        {
            switch (factory.Target.Architecture)
            {
                case TargetArchitecture.ARM64:
                    _cpuType = MachCpuType.Arm64;
                    _compactUnwindDwarfCode = 0x3_00_00_00u;
                    break;
                case TargetArchitecture.X64:
                    _cpuType = MachCpuType.X86_64;
                    _compactUnwindDwarfCode = 0x4_00_00_00u;
                    break;
                default:
                    throw new NotSupportedException("Unsupported architecture");
            }

            _targetOS = factory.Target.OperatingSystem;
        }

        protected override void EmitSectionsAndLayout()
        {
            // Layout sections. At this point we don't really care if the file offsets are correct
            // but we need to compute the virtual addresses to populate the symbol table.
            uint fileOffset = 0;
            LayoutSections(ref fileOffset, out _, out _);
        }

        private void LayoutSections(ref uint fileOffset, out uint segmentFileSize, out ulong segmentSize)
        {
            ulong virtualAddress = 0;
            uint sectionIndex = 1;

            segmentFileSize = 0;
            segmentSize = 0;
            foreach (MachSection section in _sections)
            {
                uint alignment = 1u << (int)section.Log2Alignment;

                fileOffset = (fileOffset + alignment - 1) & ~(alignment - 1);
                virtualAddress = (virtualAddress + alignment - 1) & ~(alignment - 1);

                if (section.IsInFile)
                {
                    section.FileOffset = fileOffset;
                    fileOffset += (uint)section.Size;
                    segmentFileSize = Math.Max(segmentFileSize, fileOffset);
                }
                else
                {
                    // The offset is unused for virtual sections.
                    section.FileOffset = 0;
                }

                section.VirtualAddress = virtualAddress;
                virtualAddress += section.Size;

                section.SectionIndex = sectionIndex;
                sectionIndex++;

                segmentSize = Math.Max(segmentSize, virtualAddress);
            }

            // ...and the relocation tables
            foreach (MachSection section in _sections)
            {
                section.RelocationOffset = fileOffset;
                fileOffset += section.NumberOfRelocationEntries * 8;
            }
        }

        protected override void EmitObjectFile(string objectFilePath)
        {
            _sections.Add(_compactUnwindSection);

            // Segment + sections
            uint loadCommandsCount = 1;
            uint loadCommandsSize = (uint)(MachSegment64Header.HeaderSize + _sections.Count * MachSection.HeaderSize);
            // Symbol table
            loadCommandsCount += 2;
            loadCommandsSize += (uint)(MachSymbolTableCommandHeader.HeaderSize + MachDynamicLinkEditSymbolTable.HeaderSize);
            // Build version
            loadCommandsCount++;
            loadCommandsSize += (uint)MachBuildVersionCommandHeader.HeaderSize;

            // We added the compact unwinding section, debug sections, and relocations,
            // so re-run the layout and this time calculate with the correct file offsets.
            uint fileOffset = (uint)MachHeader64.HeaderSize + loadCommandsSize;
            uint segmentFileOffset = fileOffset;
            LayoutSections(ref fileOffset, out uint segmentFileSize, out ulong segmentSize);

            using var outputFileStream = new FileStream(objectFilePath, FileMode.Create);

            MachHeader64 machHeader = new MachHeader64
            {
                Magic = MachMagic.MachHeader64LittleEndian,
                CpuType = _cpuType,
                CpuSubType = 0,
                FileType = MachFileType.Object,
                NumberOfCommands = loadCommandsCount,
                SizeOfCommands = loadCommandsSize,
                Flags = MachHeaderFlags.SubsectionsViaSymbols,
                Reserved = 0,
            };
            machHeader.Write(outputFileStream);

            MachSegment64Header machSegment64Header = new MachSegment64Header
            {
                Name = "",
                InitialProtection = MachVmProtection.Execute | MachVmProtection.Read | MachVmProtection.Write,
                MaximumProtection = MachVmProtection.Execute | MachVmProtection.Read | MachVmProtection.Write,
                Address = 0,
                Size = segmentSize,
                FileOffset = segmentFileOffset,
                FileSize = segmentFileSize,
                NumberOfSections = (uint)_sections.Count,
            };
            machSegment64Header.Write(outputFileStream);

            foreach (MachSection section in _sections)
            {
                section.WriteHeader(outputFileStream);
            }

            MachStringTable stringTable = new();
            foreach (MachSymbol symbol in _symbolTable)
            {
                stringTable.ReserveString(symbol.Name);
            }

            uint stringTableOffset = fileOffset;
            uint symbolTableOffset = stringTableOffset + ((stringTable.Size + 7u) & ~7u);
            MachSymbolTableCommandHeader symbolTableHeader = new MachSymbolTableCommandHeader
            {
                SymbolTableOffset = symbolTableOffset,
                NumberOfSymbols = (uint)_symbolTable.Count,
                StringTableOffset = stringTableOffset,
                StringTableSize = stringTable.Size,
            };
            symbolTableHeader.Write(outputFileStream);
            _dySymbolTable.Write(outputFileStream);

            // Build version
            MachBuildVersionCommandHeader buildVersion = new MachBuildVersionCommandHeader
            {
                SdkVersion = 0x10_00_00u, // 16.0.0
            };
            switch (_targetOS)
            {
                case TargetOS.OSX:
                    buildVersion.Platform = MachPlatform.MacOS;
                    buildVersion.MinimumPlatformVersion = 0x0a_0c_00; // 10.12.0
                    break;

                case TargetOS.MacCatalyst:
                    buildVersion.Platform = MachPlatform.MacCatalyst;
                    buildVersion.MinimumPlatformVersion = _cpuType switch
                    {
                        MachCpuType.X86_64 => 0x0d_05_00u, // 13.5.0
                        _ => 0x0e_02_00u, // 14.2.0
                    };
                    break;

                case TargetOS.iOS:
                case TargetOS.iOSSimulator:
                case TargetOS.tvOS:
                case TargetOS.tvOSSimulator:
                    buildVersion.Platform = _targetOS switch
                    {
                        TargetOS.iOS => MachPlatform.IOS,
                        TargetOS.iOSSimulator => MachPlatform.IOSSimulator,
                        TargetOS.tvOS => MachPlatform.TvOS,
                        TargetOS.tvOSSimulator => MachPlatform.TvOSSimulator,
                        _ => 0,
                    };
                    buildVersion.MinimumPlatformVersion = 0x0b_00_00; // 11.0.0
                    break;
            }
            buildVersion.Write(outputFileStream);

            // Write section contents
            foreach (MachSection section in _sections)
            {
                if (section.IsInFile)
                {
                    outputFileStream.Position = (long)section.FileOffset;
                    section.Stream.Position = 0;
                    section.Stream.CopyTo(outputFileStream);
                }
            }

            // Write relocations
            foreach (MachSection section in _sections)
            {
                if (section.NumberOfRelocationEntries > 0)
                {
                    foreach (MachRelocation relocation in section.Relocations)
                    {
                        relocation.Write(outputFileStream);
                    }
                }
            }

            // Write string and symbol table
            stringTable.Write(outputFileStream);
            outputFileStream.Position = symbolTableOffset;
            foreach (MachSymbol symbol in _symbolTable)
            {
                symbol.Write(outputFileStream, stringTable);
            }
        }

        protected override void CreateSection(ObjectNodeSection section, string comdatName, string symbolName, Stream sectionStream)
        {
            string segmentName = section.Name switch
            {
                "rdata" => "__TEXT",
                ".eh_frame" => "__TEXT",
                _ => section.Type switch
                {
                    SectionType.Executable => "__TEXT",
                    SectionType.Debug => "__DWARF",
                    _ => "__DATA"
                }
            };

            string sectionName = section.Name switch
            {
                "text" => "__text",
                "data" => "__data",
                "rdata" => "__const",
                "bss" => "__bss",
                ".eh_frame" => "__eh_frame",
                ".debug_info" => "__debug_info",
                ".debug_abbrev" => "__debug_abbrev",
                ".debug_ranges" => "__debug_ranges",
                ".debug_aranges" => "__debug_aranges",
                ".debug_str" => "__debug_str",
                ".debug_line" => "__debug_line",
                ".debug_loc" => "__debug_loc",
                _ => section.Name
            };

            MachSectionAttributes attributes = section.Name switch
            {
                ".dotnet_eh_table" => MachSectionAttributes.Debug,
                ".eh_frame" => MachSectionAttributes.LiveSupport | MachSectionAttributes.StripStaticSymbols | MachSectionAttributes.NoTableOfContents,
                _ => section.Type switch
                {
                    SectionType.Executable => MachSectionAttributes.SomeInstructions | MachSectionAttributes.PureInstructions,
                    SectionType.Debug => MachSectionAttributes.Debug,
                    _ => 0
                }
            };

            MachSectionType type = section.Name switch
            {
                "bss" => MachSectionType.ZeroFill,
                ".eh_frame" => MachSectionType.Coalesced,
                _ => section.Type == SectionType.Uninitialized ? MachSectionType.ZeroFill : MachSectionType.Regular
            };

            MachSection machSection = new MachSection(segmentName, sectionName, sectionStream)
            {
                Log2Alignment = 1,
                Type = type,
                Attributes = attributes,
            };

            int sectionIndex = _sections.Count;
            _sections.Add(machSection);

            if (section.Type != SectionType.Debug)
            {
                // Generate section base symbol. The section symbols are used for PC relative relocations
                // to subtract the base of the section, and in DWARF to emit section relative relocations.
                var machSymbol = new MachSymbol
                {
                    Name = $"lsection{sectionIndex}",
                    Section = machSection,
                    Value = machSection.VirtualAddress,
                    Descriptor = 0,
                    Type = MachSymbolType.Section,
                };
                _symbolTable.Add(machSymbol);
                _symbolNameToIndex[machSymbol.Name] = (uint)sectionIndex;
            }

            base.CreateSection(section, comdatName, symbolName ?? $"lsection{sectionIndex}", sectionStream);
        }

        protected internal override void UpdateSectionAlignment(int sectionIndex, int alignment)
        {
            MachSection machSection = _sections[sectionIndex];
            Debug.Assert(BitOperations.IsPow2(alignment));
            machSection.Log2Alignment = Math.Max(machSection.Log2Alignment, (uint)BitOperations.Log2((uint)alignment));
        }

        protected internal override void EmitRelocation(
            int sectionIndex,
            long offset,
            Span<byte> data,
            RelocType relocType,
            string symbolName,
            long addend)
        {
            if (relocType is RelocType.IMAGE_REL_BASED_DIR64 or RelocType.IMAGE_REL_BASED_HIGHLOW)
            {
                // Mach-O doesn't use relocations between DWARF sections, so embed the offsets directly
                MachSection machSection = _sections[sectionIndex];
                if (machSection.Attributes.HasFlag(MachSectionAttributes.Debug) &&
                    machSection.SegmentName == "__DWARF")
                {
                    // DWARF section to DWARF section relocation
                    if (symbolName.StartsWith('.'))
                    {
                        switch (relocType)
                        {
                            case RelocType.IMAGE_REL_BASED_DIR64:
                                BinaryPrimitives.WriteInt64LittleEndian(data, addend);
                                break;
                            case RelocType.IMAGE_REL_BASED_HIGHLOW:
                                BinaryPrimitives.WriteUInt32LittleEndian(data, (uint)addend);
                                break;
                            default:
                                throw new NotSupportedException("Unsupported relocation in debug section");
                        }
                        return;
                    }
                    // DWARF section to code/data section relocation
                    else
                    {
                        Debug.Assert(IsSectionSymbolName(symbolName));
                        Debug.Assert(relocType == RelocType.IMAGE_REL_BASED_DIR64);
                        int targetSectionIndex = (int)_symbolNameToIndex[symbolName];
                        BinaryPrimitives.WriteUInt64LittleEndian(data, _sections[targetSectionIndex].VirtualAddress + (ulong)addend);
                        base.EmitRelocation(sectionIndex, offset, data, relocType, symbolName, addend);
                    }

                    return;
                }
            }

            // For most relocations we write the addend directly into the
            // data. The exceptions are IMAGE_REL_BASED_ARM64_PAGEBASE_REL21
            // and IMAGE_REL_BASED_ARM64_PAGEOFFSET_12A.

            if (relocType == RelocType.IMAGE_REL_BASED_ARM64_BRANCH26)
            {
                Debug.Assert(_cpuType == MachCpuType.Arm64);
                Debug.Assert(addend == 0);
            }
            else if (relocType == RelocType.IMAGE_REL_BASED_DIR64)
            {
                if (addend != 0)
                {
                    BinaryPrimitives.WriteInt64LittleEndian(
                        data,
                        BinaryPrimitives.ReadInt64LittleEndian(data) +
                        addend);
                    addend = 0;
                }
            }
            else if (relocType == RelocType.IMAGE_REL_BASED_RELPTR32)
            {
                if (_cpuType == MachCpuType.Arm64)
                {
                    // On ARM64 we need to represent PC relative relocations as
                    // subtraction and the PC offset is baked into the addend.
                    BinaryPrimitives.WriteInt32LittleEndian(
                        data,
                        BinaryPrimitives.ReadInt32LittleEndian(data) +
                        (int)(addend - offset));
                }
                else if (sectionIndex == EhFrameSectionIndex)
                {
                    // ld64 requires X86_64_RELOC_SUBTRACTOR + X86_64_RELOC_UNSIGNED
                    // for DWARF CFI sections
                    BinaryPrimitives.WriteInt32LittleEndian(
                        data,
                        BinaryPrimitives.ReadInt32LittleEndian(data) +
                        (int)(addend - offset));
                }
                else
                {
                    addend += 4;
                    if (addend != 0)
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(
                            data,
                            BinaryPrimitives.ReadInt32LittleEndian(data) +
                            (int)addend);
                    }
                }
                addend = 0;
            }
            else if (relocType == RelocType.IMAGE_REL_BASED_REL32)
            {
                Debug.Assert(_cpuType != MachCpuType.Arm64);
                if (addend != 0)
                {
                    BinaryPrimitives.WriteInt32LittleEndian(
                        data,
                        BinaryPrimitives.ReadInt32LittleEndian(data) +
                        (int)addend);
                    addend = 0;
                }
            }

            base.EmitRelocation(sectionIndex, offset, data, relocType, symbolName, addend);
        }

        protected override void EmitSymbolTable(
            IDictionary<string, SymbolDefinition> definedSymbols,
            SortedSet<string> undefinedSymbols)
        {
            // We already emitted symbols for all non-debug sections in EmitSectionsAndLayout,
            // these symbols are local and we need to account for them.
            uint symbolIndex = (uint)_symbolTable.Count;
            _dySymbolTable.LocalSymbolsIndex = 0;
            _dySymbolTable.LocalSymbolsCount = symbolIndex;

            // Sort and insert all defined symbols
            var sortedDefinedSymbols = new List<MachSymbol>(definedSymbols.Count);
            foreach ((string name, SymbolDefinition definition) in definedSymbols)
            {
                MachSection section = _sections[definition.SectionIndex];
                sortedDefinedSymbols.Add(new MachSymbol
                {
                    Name = name,
                    Section = section,
                    Value = section.VirtualAddress + (ulong)definition.Value,
                    Descriptor = 0,
                    Type = MachSymbolType.Section | MachSymbolType.External,
                });
            }
            sortedDefinedSymbols.Sort((symA, symB) => string.CompareOrdinal(symA.Name, symB.Name));
            foreach (MachSymbol definedSymbol in sortedDefinedSymbols)
            {
                _symbolTable.Add(definedSymbol);
                _symbolNameToIndex[definedSymbol.Name] = symbolIndex;
                symbolIndex++;
            }

            _dySymbolTable.ExternalSymbolsIndex = _dySymbolTable.LocalSymbolsCount;
            _dySymbolTable.ExternalSymbolsCount = (uint)definedSymbols.Count;

            uint savedSymbolIndex = symbolIndex;
            foreach (string externSymbol in undefinedSymbols)
            {
                if (!_symbolNameToIndex.ContainsKey(externSymbol))
                {
                    var machSymbol = new MachSymbol
                    {
                        Name = externSymbol,
                        Section = null,
                        Value = 0,
                        Descriptor = 0,
                        Type = MachSymbolType.Undefined | MachSymbolType.External,
                    };
                    _symbolTable.Add(machSymbol);
                    _symbolNameToIndex[externSymbol] = symbolIndex;
                    symbolIndex++;
                }
            }

            _dySymbolTable.UndefinedSymbolsIndex = _dySymbolTable.LocalSymbolsCount + _dySymbolTable.ExternalSymbolsCount;
            _dySymbolTable.UndefinedSymbolsCount = symbolIndex - savedSymbolIndex;

            EmitCompactUnwindTable(definedSymbols);
        }

        protected override void EmitRelocations(int sectionIndex, List<SymbolicRelocation> relocationList)
        {
            if (_cpuType == MachCpuType.Arm64)
            {
                EmitRelocationsArm64(sectionIndex, relocationList);
            }
            else
            {
                EmitRelocationsX64(sectionIndex, relocationList);
            }
        }

        private void EmitRelocationsX64(int sectionIndex, List<SymbolicRelocation> relocationList)
        {
            ICollection<MachRelocation> sectionRelocations = _sections[sectionIndex].Relocations;

            relocationList.Reverse();
            foreach (SymbolicRelocation symbolicRelocation in relocationList)
            {
                uint symbolIndex = _symbolNameToIndex[symbolicRelocation.SymbolName];

                if (symbolicRelocation.Type == RelocType.IMAGE_REL_BASED_DIR64)
                {
                    bool isExternal = !IsSectionSymbolName(symbolicRelocation.SymbolName);
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = isExternal ? symbolIndex : symbolIndex + 1,
                            Length = 8,
                            RelocationType = MachRelocationType.X86_64Unsigned,
                            IsExternal = isExternal,
                            IsPCRelative = false,
                        });
                }
                else if (symbolicRelocation.Type == RelocType.IMAGE_REL_BASED_RELPTR32 && sectionIndex == EhFrameSectionIndex)
                {
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = (uint)sectionIndex,
                            Length = 4,
                            RelocationType = MachRelocationType.X86_64Subtractor,
                            IsExternal = true,
                            IsPCRelative = false,
                        });
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = symbolIndex,
                            Length = 4,
                            RelocationType = MachRelocationType.X86_64Unsigned,
                            IsExternal = true,
                            IsPCRelative = false,
                        });
                }
                else if (symbolicRelocation.Type is RelocType.IMAGE_REL_BASED_RELPTR32 or RelocType.IMAGE_REL_BASED_REL32)
                {
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = symbolIndex,
                            Length = 4,
                            RelocationType = MachRelocationType.X86_64Branch,
                            IsExternal = true,
                            IsPCRelative = true,
                        });
                }
                else
                {
                    throw new NotSupportedException("Unknown relocation type: " + symbolicRelocation.Type);
                }
            }
        }

        private void EmitRelocationsArm64(int sectionIndex, List<SymbolicRelocation> relocationList)
        {
            ICollection<MachRelocation> sectionRelocations = _sections[sectionIndex].Relocations;

            relocationList.Reverse();
            foreach (SymbolicRelocation symbolicRelocation in relocationList)
            {
                uint symbolIndex = _symbolNameToIndex[symbolicRelocation.SymbolName];

                if (symbolicRelocation.Type == RelocType.IMAGE_REL_BASED_ARM64_BRANCH26)
                {
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = symbolIndex,
                            Length = 4,
                            RelocationType = MachRelocationType.Arm64Branch26,
                            IsExternal = true,
                            IsPCRelative = true,
                        });
                }
                else if (symbolicRelocation.Type is RelocType.IMAGE_REL_BASED_ARM64_PAGEBASE_REL21 or RelocType.IMAGE_REL_BASED_ARM64_PAGEOFFSET_12A)
                {
                    if (symbolicRelocation.Addend != 0)
                    {
                        sectionRelocations.Add(
                            new MachRelocation
                            {
                                Address = (int)symbolicRelocation.Offset,
                                SymbolOrSectionIndex = (uint)symbolicRelocation.Addend,
                                Length = 4,
                                RelocationType = MachRelocationType.Arm64Addend,
                                IsExternal = false,
                                IsPCRelative = false,
                            });
                    }

                    MachRelocationType type = symbolicRelocation.Type switch
                    {
                        RelocType.IMAGE_REL_BASED_ARM64_PAGEBASE_REL21 => MachRelocationType.Arm64Page21,
                        RelocType.IMAGE_REL_BASED_ARM64_PAGEOFFSET_12A => MachRelocationType.Arm64PageOffset21,
                        _ => 0
                    };

                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = symbolIndex,
                            Length = 4,
                            RelocationType = type,
                            IsExternal = true,
                            IsPCRelative = symbolicRelocation.Type != RelocType.IMAGE_REL_BASED_ARM64_PAGEOFFSET_12A,
                        });
                }
                else if (symbolicRelocation.Type == RelocType.IMAGE_REL_BASED_DIR64)
                {
                    bool isExternal = !IsSectionSymbolName(symbolicRelocation.SymbolName);
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = isExternal ? symbolIndex : symbolIndex + 1,
                            Length = 8,
                            RelocationType = MachRelocationType.Arm64Unsigned,
                            IsExternal = isExternal,
                            IsPCRelative = false,
                        });
                }
                else if (symbolicRelocation.Type == RelocType.IMAGE_REL_BASED_RELPTR32)
                {
                    // This one is tough... needs to be represented by ARM64_RELOC_SUBTRACTOR + ARM64_RELOC_UNSIGNED.
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = (uint)sectionIndex,
                            Length = 4,
                            RelocationType = MachRelocationType.Arm64Subtractor,
                            IsExternal = true,
                            IsPCRelative = false,
                        });
                    sectionRelocations.Add(
                        new MachRelocation
                        {
                            Address = (int)symbolicRelocation.Offset,
                            SymbolOrSectionIndex = symbolIndex,
                            Length = 4,
                            RelocationType = MachRelocationType.Arm64Unsigned,
                            IsExternal = true,
                            IsPCRelative = false,
                        });
                }
                else
                {
                    throw new NotSupportedException("Unknown relocation type: " + symbolicRelocation.Type);
                }
            }
        }

        private void EmitCompactUnwindTable(IDictionary<string, SymbolDefinition> definedSymbols)
        {
            _compactUnwindStream = new MemoryStream(32 * _compactUnwindCodes.Count);
            // Preset the size of the compact unwind section which is not generated yet
            _compactUnwindStream.SetLength(32 * _compactUnwindCodes.Count);

            _compactUnwindSection = new MachSection("__LD", "__compact_unwind", _compactUnwindStream)
            {
                Log2Alignment = 3,
                Type = MachSectionType.Regular,
                Attributes = MachSectionAttributes.Debug,
            };

            IList<MachSymbol> symbols = _symbolTable;
            Span<byte> tempBuffer = stackalloc byte[8];
            foreach (var cu in _compactUnwindCodes)
            {
                EmitCompactUnwindSymbol(cu.PcStartSymbolName);
                BinaryPrimitives.WriteUInt32LittleEndian(tempBuffer, cu.PcLength);
                BinaryPrimitives.WriteUInt32LittleEndian(tempBuffer.Slice(4), cu.Code);
                _compactUnwindStream.Write(tempBuffer);
                EmitCompactUnwindSymbol(cu.PersonalitySymbolName);
                EmitCompactUnwindSymbol(cu.LsdaSymbolName);
            }

            void EmitCompactUnwindSymbol(string symbolName)
            {
                Span<byte> tempBuffer = stackalloc byte[8];
                if (symbolName != null)
                {
                    SymbolDefinition symbol = definedSymbols[symbolName];
                    MachSection section = _sections[symbol.SectionIndex];
                    BinaryPrimitives.WriteUInt64LittleEndian(tempBuffer, section.VirtualAddress + (ulong)symbol.Value);
                    _compactUnwindSection.Relocations.Add(
                        new MachRelocation
                        {
                            Address = (int)_compactUnwindStream.Position,
                            SymbolOrSectionIndex = (byte)(1 + symbol.SectionIndex), // 1-based
                            Length = 8,
                            RelocationType = MachRelocationType.Arm64Unsigned,
                            IsExternal = false,
                            IsPCRelative = false,
                        }
                    );
                }
                _compactUnwindStream.Write(tempBuffer);
            }
        }

        protected override string ExternCName(string name) => "_" + name;

        // This represents the following DWARF code:
        //   DW_CFA_advance_loc: 4
        //   DW_CFA_def_cfa_offset: +16
        //   DW_CFA_offset: W29 -16
        //   DW_CFA_offset: W30 -8
        //   DW_CFA_advance_loc: 4
        //   DW_CFA_def_cfa_register: W29
        // which is generated for the following frame prolog/epilog:
        //   stp fp, lr, [sp, #-10]!
        //   mov fp, sp
        //   ...
        //   ldp fp, lr, [sp], #0x10
        //   ret
        private static ReadOnlySpan<byte> DwarfArm64EmptyFrame => new byte[]
        {
            0x04, 0x00, 0xFF, 0xFF, 0x10, 0x00, 0x00, 0x00,
            0x04, 0x02, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x04, 0x02, 0x1E, 0x00, 0x08, 0x00, 0x00, 0x00,
            0x08, 0x01, 0x1D, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        protected override bool EmitCompactUnwinding(string startSymbolName, ulong length, string lsdaSymbolName, byte[] blob)
        {
            uint encoding = _compactUnwindDwarfCode;

            if (_cpuType == MachCpuType.Arm64)
            {
                if (blob.AsSpan().SequenceEqual(DwarfArm64EmptyFrame))
                {
                    // Frame-based encoding, no saved registers
                    encoding = 0x04000000;
                }
            }

            _compactUnwindCodes.Add(new CompactUnwindCode(
                PcStartSymbolName: startSymbolName,
                PcLength: (uint)length,
                Code: encoding | (encoding != _compactUnwindDwarfCode && lsdaSymbolName != null ? 0x40000000u : 0), // UNWIND_HAS_LSDA
                LsdaSymbolName: encoding != _compactUnwindDwarfCode ? lsdaSymbolName : null
            ));

            return encoding != _compactUnwindDwarfCode;
        }

        private static bool IsSectionSymbolName(string symbolName) => symbolName.StartsWith('l');

        public enum MachMagic : uint
        {
            MachHeaderLittleEndian = 0xcefaedfe,
            MachHeaderBigEndian = 0xfeedface,
            MachHeader64LittleEndian = 0xcffaedfe,
            MachHeader64BigEndian = 0xfeedfacf,
            FatMagicLittleEndian = 0xbebafeca,
            FatMagicBigEndian = 0xcafebabe,
        }

        public enum MachFileType : uint
        {
            Object = 1,
        }

        public enum MachCpuType : uint
        {
            X86 = 7,
            X86_64 = X86 | Architecture64,
            Arm = 12,
            Arm64 = Arm | Architecture64,
            Architecture64 = 0x1000000,
        }

        [Flags]
        public enum MachHeaderFlags : uint
        {
            NoUndefinedReferences = 0x1,
            IncrementalLink = 0x2,
            DynamicLink = 0x4,
            BindAtLoad = 0x8,
            Prebound = 0x10,
            SplitSegments = 0x20,
            LazyInit = 0x40,
            TwoLevel = 0x80,
            ForceFlat = 0x100,
            NoMultiDefs = 0x200,
            NoFixPrebinding = 0x400,
            Prebindable = 0x800,
            AllModsBound = 0x1000,
            SubsectionsViaSymbols = 0x2000,
            Canonical = 0x4000,
            WeakDefines = 0x8000,
            BindsToWeak = 0x10000,
            AllowStackExecution = 0x20000,
            RootSafe = 0x40000,
            SetuidSafe = 0x80000,
            NoReexportedDylibs = 0x100000,
            PIE = 0x200000,
            DeadStrippableDylib = 0x400000,
            HasTlvDescriptors = 0x800000,
            NoHeapExecution = 0x1000000
        }

        private struct MachHeader64
        {
            public MachMagic Magic { get; set; }
            public MachCpuType CpuType { get; set; }
            public uint CpuSubType { get; set; }
            public MachFileType FileType { get; set; }
            public uint NumberOfCommands { get; set; }
            public uint SizeOfCommands { get; set; }
            public MachHeaderFlags Flags { get; set; }
            public uint Reserved { get; set; }

            public static int HeaderSize => 32;

            public void Write(FileStream stream)
            {
                Span<byte> buffer = stackalloc byte[HeaderSize];

                BinaryPrimitives.WriteUInt32BigEndian(buffer.Slice(0, 4), (uint)Magic);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(4, 4), (uint)CpuType);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(8, 4), CpuSubType);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(12, 4), (uint)FileType);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(16, 4), NumberOfCommands);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(20, 4), SizeOfCommands);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(24, 4), (uint)Flags);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(28, 4), Reserved);

                stream.Write(buffer);
            }
        }

        public enum MachLoadCommandType : uint
        {
            SymbolTable = 0x2,
            DynamicLinkEditSymbolTable = 0xb,
            Segment64 = 0x19,
            BuildVersion = 0x32,
        }

        [Flags]
        public enum MachVmProtection : uint
        {
            None = 0x0,
            Read = 0x1,
            Write = 0x2,
            Execute = 0x4,
        }

        [Flags]
        public enum MachSegmentFlags : uint
        {
            HighVirtualMemory = 1,
            NoRelocations = 4,
        }

        public struct MachSegment64Header
        {
            public string Name { get; set; }
            public ulong Address { get; set; }
            public ulong Size { get; set; }
            public ulong FileOffset { get; set; }
            public ulong FileSize { get; set; }
            public MachVmProtection MaximumProtection { get; set; }
            public MachVmProtection InitialProtection { get; set; }
            public uint NumberOfSections { get; set; }
            public MachSegmentFlags Flags { get; set; }

            public static int HeaderSize => 72;

            public void Write(FileStream stream)
            {
                Span<byte> buffer = stackalloc byte[HeaderSize];

                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(0, 4), (uint)MachLoadCommandType.Segment64);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(4, 4), (uint)(HeaderSize + NumberOfSections * MachSection.HeaderSize));
                Debug.Assert(Encoding.UTF8.TryGetBytes(Name, buffer.Slice(8, 16), out _));
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(24, 8), Address);
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(32, 8), Size);
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(40, 8), FileOffset);
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(48, 8), FileSize);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(56, 4), (uint)MaximumProtection);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(60, 4), (uint)InitialProtection);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(64, 4), NumberOfSections);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(68, 4), (uint)Flags);

                stream.Write(buffer);
            }
        }

        [Flags]
        private enum MachSectionAttributes : uint
        {
            LocalRelocations = 0x100,
            ExternalRelocations = 0x200,
            SomeInstructions = 0x400,
            Debug = 0x2000000,
            SelfModifyingCode = 0x4000000,
            LiveSupport = 0x8000000,
            NoDeadStrip = 0x10000000,
            StripStaticSymbols = 0x20000000,
            NoTableOfContents = 0x40000000,
            PureInstructions = 0x80000000,
        }

        private enum MachSectionType : byte
        {
            Regular = 0,
            ZeroFill = 1,
            CStringLiterals = 2,
            FourByteLiterals = 3,
            EightByteLiterals = 4,
            LiteralPointers = 5,
            NonLazySymbolPointers = 6,
            LazySymbolPointers = 7,
            SymbolStubs = 8,
            ModInitFunctionPointers = 9,
            ModTermFunctionPointers = 10,
            Coalesced = 11,
            GBZeroFill = 12,
            Interposing = 13,
            SixteenByteLiterals = 14,
            DTraceObjectFormat = 15,
            LazyDylibSymbolPointers = 16,
            ThreadLocalRegular = 17,
            ThreadLocalZeroFill = 18,
            ThreadLocalVariables = 19,
            ThreadLocalVariablePointers = 20,
            ThreadLocalInitFunctionPointers = 21,
        }

        private sealed class MachSection
        {
            private Stream dataStream;
            private List<MachRelocation> relocationCollection;

            public static int HeaderSize => 80; // 64-bit section

            public MachSection(string segmentName, string sectionName, Stream stream)
            {
                ArgumentNullException.ThrowIfNull(segmentName);
                ArgumentNullException.ThrowIfNull(sectionName);

                this.SegmentName = segmentName;
                this.SectionName = sectionName;
                this.dataStream = stream;
                this.relocationCollection = null;
            }

            public void WriteHeader(FileStream stream)
            {
                Span<byte> buffer = stackalloc byte[HeaderSize];

                buffer.Clear();
                Debug.Assert(Encoding.UTF8.TryGetBytes(SectionName, buffer.Slice(0, 16), out _));
                Debug.Assert(Encoding.UTF8.TryGetBytes(SegmentName, buffer.Slice(16, 16), out _));
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(32, 8), VirtualAddress);
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(40, 8), Size);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(48, 4), FileOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(52, 4), Log2Alignment);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(56, 4), RelocationOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(60, 4), NumberOfRelocationEntries);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(64, 4), Flags);
                //BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(68, 4), Reserved1);
                //BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(72, 4), Reserved2);
                //BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(76, 4), Reserved3);

                stream.Write(buffer);
            }

            public string SectionName { get; private init; }
            public string SegmentName { get; private init; }
            public ulong VirtualAddress { get; set; }
            public ulong Size => (ulong)dataStream.Length;
            public uint FileOffset { get; set; }
            public uint Log2Alignment { get; set; }
            public uint RelocationOffset { get; set; }
            public uint NumberOfRelocationEntries => relocationCollection is null ? 0u : (uint)relocationCollection.Count;
            internal uint Flags { get; set; }

            public uint SectionIndex { get; set; }

            public MachSectionAttributes Attributes
            {
                get => (MachSectionAttributes)(Flags & ~0xffu);
                set => Flags = (Flags & 0xffu) | (uint)value;
            }

            public MachSectionType Type
            {
                get => (MachSectionType)(Flags & 0xff);
                set => Flags = (Flags & ~0xffu) | (uint)value;
            }

            public bool IsInFile => Size > 0 && Type != MachSectionType.ZeroFill && Type != MachSectionType.GBZeroFill && Type != MachSectionType.ThreadLocalZeroFill;

            public IList<MachRelocation> Relocations => relocationCollection ??= new List<MachRelocation>();

            public Stream Stream => dataStream;
        }

        private enum MachRelocationType : byte
        {
            GenericVanilla = 0,
            GenericPair = 1,
            GenericSectionDiff = 2,
            GenericPreboundLazyPtr = 3,
            GenericLocalSectionDiff = 4,
            GenericTlv = 5,

            X86_64Unsigned = 0,
            X86_64Signed = 1,
            X86_64Branch = 2,
            X86_64GotLoad = 3,
            X86_64Got = 4,
            X86_64Subtractor = 5,
            X86_64Signed1 = 6,
            X86_64Signed2 = 7,
            X86_64Signed4 = 8,
            X86_64Tlv = 9,

            Arm64Unsigned = 0,
            Arm64Subtractor = 1,
            Arm64Branch26 = 2,
            Arm64Page21 = 3,
            Arm64PageOffset21 = 4,
            Arm64GotLoadPage21 = 5,
            Arm64GotLoadPageOffset21 = 6,
            Arm64PointerToGot = 7,
            Arm64TlvpLoadPage21 = 8,
            Arm64TlvpLoadPageOffset21 = 9,
            Arm64Addend = 10,
        }

        private sealed class MachRelocation
        {
            public int Address { get; init; }
            public uint SymbolOrSectionIndex { get; init; }
            public bool IsPCRelative { get; init; }
            public bool IsExternal { get; init; }
            public byte Length { get; init; }
            public MachRelocationType RelocationType { get; init; }

            public void Write(FileStream stream)
            {
                Span<byte> relocationBuffer = stackalloc byte[8];
                uint info = SymbolOrSectionIndex;
                info |= IsPCRelative ? 0x1_00_00_00u : 0u;
                info |= Length switch { 1 => 0u << 25, 2 => 1u << 25, 4 => 2u << 25, _ => 3u << 25 };
                info |= IsExternal ? 0x8_00_00_00u : 0u;
                info |= (uint)RelocationType << 28;
                BinaryPrimitives.WriteInt32LittleEndian(relocationBuffer, Address);
                BinaryPrimitives.WriteUInt32LittleEndian(relocationBuffer.Slice(4), info);
                stream.Write(relocationBuffer);
            }
        }

        [Flags]
        private enum MachSymbolType : byte
        {
            Stab = 0xe0,
            PrivateExternal = 0x10,

            TypeMask = 0xe,

            Undefined = 0,
            External = 1,
            Section = 0xe,
            Prebound = 0xc,
            Indirect = 0xa,
        }

        [Flags]
        private enum MachSymbolDescriptor : ushort
        {
            ReferenceTypeMask = 0xf,
            UndefinedNonLazy = 0,
            UndefinedLazy = 1,
            Defined = 2,
            PrivateDefined = 3,
            PrivateUndefinedNonLazy = 4,
            PrivateUndefinedLazy = 5,

            ReferencedDynamically = 0x10,
            NoDeadStrip = 0x20,
            WeakReference = 0x40,
            WeakDefinition = 0x80,
        }

        private sealed class MachSymbol
        {
            public string Name { get; init; } = string.Empty;
            public MachSymbolType Type { get; init; }
            public MachSection Section { get; init; }
            public MachSymbolDescriptor Descriptor { get; init; }
            public ulong Value { get; init; }

            public bool IsExternal => Type.HasFlag(MachSymbolType.External);
            public bool IsUndefined => (Type & MachSymbolType.TypeMask) == MachSymbolType.Undefined;

            public void Write(FileStream stream, MachStringTable stringTable)
            {
                Span<byte> buffer = stackalloc byte[16];
                uint nameIndex = stringTable.GetStringOffset(Name);

                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(0, 4), nameIndex);
                buffer[4] = (byte)Type;
                buffer[5] = (byte)(Section?.SectionIndex ?? 0);
                BinaryPrimitives.WriteUInt16LittleEndian(buffer.Slice(6, 2), (ushort)Descriptor);
                BinaryPrimitives.WriteUInt64LittleEndian(buffer.Slice(8), Value);

                stream.Write(buffer);
            }
        }

        private sealed class MachSymbolTableCommandHeader
        {
            public uint SymbolTableOffset { get; set; }
            public uint NumberOfSymbols { get; set; }
            public uint StringTableOffset { get; set; }
            public uint StringTableSize { get; set; }

            public static int HeaderSize => 24;

            public void Write(FileStream stream)
            {
                Span<byte> buffer = stackalloc byte[HeaderSize];

                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(0, 4), (uint)MachLoadCommandType.SymbolTable);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(4, 4), (uint)HeaderSize);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(8, 4), SymbolTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(12, 4), NumberOfSymbols);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(16, 4), StringTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(20, 4), StringTableSize);

                stream.Write(buffer);
            }
        }

        private sealed class MachDynamicLinkEditSymbolTable
        {
            public uint LocalSymbolsIndex { get; set; }
            public uint LocalSymbolsCount { get; set; }
            public uint ExternalSymbolsIndex { get; set; }
            public uint ExternalSymbolsCount { get; set; }
            public uint UndefinedSymbolsIndex { get; set; }
            public uint UndefinedSymbolsCount { get; set; }
            public uint TableOfContentsOffset { get; set; }
            public uint TableOfContentsCount { get; set; }
            public uint ModuleTableOffset { get; set; }
            public uint ModuleTableCount { get; set; }
            public uint ExternalReferenceTableOffset { get; set; }
            public uint ExternalReferenceTableCount { get; set; }
            public uint IndirectSymbolTableOffset { get; set; }
            public uint IndirectSymbolTableCount { get; set; }
            public uint ExternalRelocationTableOffset { get; set; }
            public uint ExternalRelocationTableCount { get; set; }
            public uint LocalRelocationTableOffset { get; set; }
            public uint LocalRelocationTableCount { get; set; }

            public static int HeaderSize => 80;

            public void Write(FileStream stream)
            {
                Span<byte> buffer = stackalloc byte[HeaderSize];

                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(0, 4), (uint)MachLoadCommandType.DynamicLinkEditSymbolTable);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(4, 4), (uint)HeaderSize);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(8, 4), LocalSymbolsIndex);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(12, 4), LocalSymbolsCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(16, 4), ExternalSymbolsIndex);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(20, 4), ExternalSymbolsCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(24, 4), UndefinedSymbolsIndex);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(28, 4), UndefinedSymbolsCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(32, 4), TableOfContentsOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(36, 4), TableOfContentsCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(40, 4), ModuleTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(44, 4), ModuleTableCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(48, 4), ExternalReferenceTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(52, 4), ExternalReferenceTableCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(56, 4), IndirectSymbolTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(60, 4), IndirectSymbolTableCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(64, 4), ExternalRelocationTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(68, 4), ExternalRelocationTableCount);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(72, 4), LocalRelocationTableOffset);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(76, 4), LocalRelocationTableCount);

                stream.Write(buffer);
            }
        }

        public enum MachPlatform : uint
        {
            MacOS = 1,
            IOS = 2,
            TvOS = 3,
            WatchOS = 4,
            BridgeOS = 5,
            MacCatalyst = 6,
            IOSSimulator = 7,
            TvOSSimulator = 8,
            WatchOSSimulator = 9,
            DriverKit = 10,
        }

        private struct MachBuildVersionCommandHeader
        {
            public MachPlatform Platform;
            public uint MinimumPlatformVersion { get; set; }
            public uint SdkVersion { get; set; }

            public static int HeaderSize => 24;

            public void Write(FileStream stream)
            {
                Span<byte> buffer = stackalloc byte[HeaderSize];

                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(0, 4), (uint)MachLoadCommandType.BuildVersion);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(4, 4), (uint)HeaderSize);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(8, 4), (uint)Platform);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(12, 4), (uint)MinimumPlatformVersion);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(16, 4), (uint)SdkVersion);
                BinaryPrimitives.WriteUInt32LittleEndian(buffer.Slice(20, 4), 0); // No tools

                stream.Write(buffer);
            }
        }

        private sealed class MachStringTable : StringTableBuilder
        {
            public MachStringTable()
            {
                // Always start the table with empty string
                GetStringOffset("");
            }
        }
    }
}
