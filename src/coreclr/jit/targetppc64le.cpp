// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*****************************************************************************/

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

#if defined(TARGET_POWERPC64)

#include "target.h"

const char*            Target::g_tgtCPUName           = "ppc64le";
const Target::ArgOrder Target::g_tgtArgOrder          = ARG_ORDER_R2L;
const Target::ArgOrder Target::g_tgtUnmanagedArgOrder = ARG_ORDER_R2L;

// clang-format off
const regNumber intArgRegs [] = {REG_R3, REG_R4, REG_R5, REG_R6, REG_R7, REG_R8, REG_R9, REG_R10};
const regMaskTP intArgMasks[] = {RBM_R3, RBM_R4, RBM_R5, RBM_R6, RBM_R7, RBM_R8, RBM_R9, RBM_R10};

const regNumber fltArgRegs [] = {REG_F1, REG_F2, REG_F3, REG_F4, REG_F5, REG_F6, REG_F7, REG_F8, REG_F9, REG_F10, REG_F11, REG_F12, REG_F13};
const regMaskTP fltArgMasks[] = {RBM_F1, RBM_F2, RBM_F3, RBM_F4, RBM_F5, RBM_F6, RBM_F7, RBM_F8, RBM_F9, RBM_F10, RBM_F11, RBM_F12, RBM_F13};
// clang-format on

//-----------------------------------------------------------------------------
// Ppc64leClassifier:
//   Construct a new instance of the PowerPC64 ELFv2 ABI classifier.
//
// Parameters:
//   info - Info about the method being classified.
//
Ppc64leClassifier::Ppc64leClassifier(const ClassifierInfo& info)
    : m_info(info)
    , m_intRegs(intArgRegs, ArrLen(intArgRegs))
    , m_floatRegs(fltArgRegs, ArrLen(fltArgRegs))
{
    if (m_info.IsVarArgs)
    {
        NYI_POWERPC64("PPC64LE varargs support");
    }
}

//-----------------------------------------------------------------------------
// Classify:
//   Classify a parameter for the PowerPC64 ELFv2 ABI.
//
// Parameters:
//   comp           - Compiler instance.
//   type           - The type of the parameter.
//   structLayout   - The layout of the struct. Expected to be non-null if
//                    varTypeIsStruct(type) is true.
//   wellKnownParam - Well known type of the parameter (if it may affect its ABI classification).
//
// Returns:
//   Classification information for the parameter.
//
ABIPassingInformation Ppc64leClassifier::Classify(Compiler*    comp,
                                                  var_types    type,
                                                  ClassLayout* structLayout,
                                                  WellKnownArg /*wellKnownParam*/)
{
    const bool isManagedCall = m_info.CallConv == CorInfoCallConvExtension::Managed;

    bool      isHfaStruct = false;
    var_types hfaType     = TYP_UNDEF;
    unsigned  hfaElemSize = 0;

    unsigned intFields  = 0;
    unsigned floatFields = 0;
    unsigned passedSize;
    bool     passedByRef = false;

    if (varTypeIsStruct(type))
    {
        passedSize = structLayout->GetSize();
        if (isManagedCall && (passedSize > MAX_PASS_MULTIREG_BYTES))
        {
            passedByRef = true;
            passedSize  = TARGET_POINTER_SIZE;
        }
        else if (!structLayout->IsBlockLayout())
        {
            CORINFO_CLASS_HANDLE classHandle = structLayout->GetClassHandle();
            isHfaStruct                      = comp->IsHfa(classHandle);
            if (isHfaStruct)
            {
                hfaType     = comp->GetHfaType(classHandle);
                hfaElemSize = genTypeSize(hfaType);
                floatFields = comp->GetHfaCount(classHandle);
                assert(varTypeIsFloating(hfaType));
                assert((floatFields >= 1) && (floatFields <= MAX_MULTIREG_COUNT));
                assert(passedSize == (floatFields * hfaElemSize));
            }
        }
    }
    else
    {
        passedSize = genTypeSize(type);
        assert(passedSize <= TARGET_POINTER_SIZE);
        floatFields = varTypeIsFloating(type) ? 1 : 0;
    }

    assert((floatFields > 0) || (intFields == 0));

    auto passOnStack = [this](unsigned offset, unsigned size) -> ABIPassingSegment {
        assert(size > 0);
        assert((m_stackArgSize % TARGET_POINTER_SIZE) == 0);
        ABIPassingSegment seg = ABIPassingSegment::OnStack(m_stackArgSize, offset, size);
        m_stackArgSize += roundUp(size, TARGET_POINTER_SIZE);
        return seg;
    };

    auto consumeParameterSlots = [this](unsigned slots) {
        assert(slots > 0);

        for (unsigned i = 0; i < slots; i++)
        {
            if (m_intRegs.Count() > 0)
            {
                m_intRegs.Dequeue();
            }
            else
            {
                m_stackArgSize += TARGET_POINTER_SIZE;
            }
        }
    };

    if (!isManagedCall && varTypeIsStruct(type) && !passedByRef && (floatFields == 0) && (intFields == 0) &&
        (m_intRegs.Count() > 0))
    {
        const unsigned numSegments = roundUp(passedSize, TARGET_POINTER_SIZE) / TARGET_POINTER_SIZE;

        const unsigned numRegSegments = min(m_intRegs.Count(), numSegments);
        const bool     hasStackSegment = numRegSegments < numSegments;
        ABIPassingInformation info(comp, numRegSegments + (hasStackSegment ? 1 : 0));

        for (unsigned i = 0; i < numRegSegments; i++)
        {
            unsigned offset = i * TARGET_POINTER_SIZE;
            unsigned size   = min(passedSize - offset, static_cast<unsigned>(TARGET_POINTER_SIZE));
            info.Segment(i) = ABIPassingSegment::InRegister(m_intRegs.Dequeue(), offset, size);
        }

        if (hasStackSegment)
        {
            unsigned offset              = numRegSegments * TARGET_POINTER_SIZE;
            info.Segment(numRegSegments) = passOnStack(offset, passedSize - offset);
        }

        return info;
    }

    if ((floatFields > 0) && (m_floatRegs.Count() >= floatFields) && (m_intRegs.Count() >= intFields))
    {
        if ((floatFields == 1) && (intFields == 0))
        {
            unsigned size = passedSize;
            if (isHfaStruct)
            {
                type = hfaType;
                size = hfaElemSize;
            }
            assert(varTypeIsFloating(type));

            ABIPassingSegment seg = ABIPassingSegment::InRegister(m_floatRegs.Dequeue(), 0, size);
            // PPC64 ELFv2 maps every fixed argument to an ordered parameter slot.
            // Floating-point values are passed in FPRs, but they still consume
            // the corresponding GPR/stack slot that determines where the
            // following non-FP argument is passed.
            consumeParameterSlots(1);
            return ABIPassingInformation::FromSegmentByValue(comp, seg);
        }
        else
        {
            assert(varTypeIsStruct(type));
            assert(isHfaStruct);
            assert(intFields == 0);
            assert(floatFields <= MAX_MULTIREG_COUNT);

            ABIPassingInformation info(comp, floatFields);
            for (unsigned i = 0; i < floatFields; i++)
            {
                info.Segment(i) = ABIPassingSegment::InRegister(m_floatRegs.Dequeue(), i * hfaElemSize, hfaElemSize);
            }
            consumeParameterSlots(roundUp(passedSize, TARGET_POINTER_SIZE) / TARGET_POINTER_SIZE);
            return info;
        }
    }

    if (isHfaStruct)
    {
        return ABIPassingInformation::FromSegmentByValue(comp, passOnStack(0, passedSize));
    }

    if (m_intRegs.Count() > 0)
    {
        if (passedSize <= TARGET_POINTER_SIZE)
        {
            ABIPassingSegment seg = ABIPassingSegment::InRegister(m_intRegs.Dequeue(), 0, passedSize);
            return ABIPassingInformation::FromSegment(comp, passedByRef, seg);
        }

        assert(varTypeIsStruct(type));
        unsigned int tailSize = passedSize - TARGET_POINTER_SIZE;

        ABIPassingSegment head = ABIPassingSegment::InRegister(m_intRegs.Dequeue(), 0, TARGET_POINTER_SIZE);
        ABIPassingSegment tail = (m_intRegs.Count() > 0)
                                     ? ABIPassingSegment::InRegister(m_intRegs.Dequeue(), TARGET_POINTER_SIZE, tailSize)
                                     : passOnStack(TARGET_POINTER_SIZE, tailSize);
        return ABIPassingInformation::FromSegments(comp, head, tail);
    }

    return ABIPassingInformation::FromSegment(comp, passedByRef, passOnStack(0, passedSize));
}

#endif // TARGET_POWERPC64
