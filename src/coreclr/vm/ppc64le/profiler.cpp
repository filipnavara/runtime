// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "common.h"

#ifdef PROFILING_SUPPORTED
#include "asmconstants.h"
#include "proftoeeinterfaceimpl.h"

UINT_PTR ProfileGetIPFromPlatformSpecificHandle(void* pPlatformSpecificHandle)
{
    LIMITED_METHOD_CONTRACT;

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(pPlatformSpecificHandle);
    return (UINT_PTR)pData->Pc;
}

void ProfileSetFunctionIDInPlatformSpecificHandle(void* pPlatformSpecificHandle, FunctionID functionId)
{
    LIMITED_METHOD_CONTRACT;

    _ASSERTE(pPlatformSpecificHandle != nullptr);
    _ASSERTE(functionId != 0);

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(pPlatformSpecificHandle);
    pData->functionId = functionId;
}

static BYTE* GetProfiledStackArgBase(PROFILE_PLATFORM_SPECIFIC_DATA* pData)
{
    LIMITED_METHOD_CONTRACT;

    const int ppc64leStackArgBias = TransitionBlock::GetOffsetOfArgs() - sizeof(TransitionBlock);
    return reinterpret_cast<BYTE*>(pData->profiledSp) + ppc64leStackArgBias;
}

static BYTE* GetProfiledStackArg(PROFILE_PLATFORM_SPECIFIC_DATA* pData, int byteStackIndex)
{
    LIMITED_METHOD_CONTRACT;

    _ASSERTE(byteStackIndex >= 0);
    return GetProfiledStackArgBase(pData) + byteStackIndex;
}

ProfileArgIterator::ProfileArgIterator(MetaSig* pSig, void* pPlatformSpecificHandle)
    : m_argIterator(pSig), m_bufferPos(0)
{
    WRAPPER_NO_CONTRACT;

    _ASSERTE(pSig != nullptr);
    _ASSERTE(pPlatformSpecificHandle != nullptr);

    m_handle = pPlatformSpecificHandle;

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(pPlatformSpecificHandle);

    MethodDesc* pMD = FunctionIdToMethodDesc(pData->functionId);

    if ((pData->hiddenArg == nullptr) && (pMD->RequiresInstArg() || pMD->AcquiresInstMethodTableFromThis()))
    {
        if ((pData->flags & PROFILE_ENTER) != 0)
        {
            if (pMD->AcquiresInstMethodTableFromThis())
            {
                pData->hiddenArg = GetThis();
            }
            else
            {
                pData->hiddenArg =
                    (void*)pData->argumentRegisters.r[m_argIterator.HasThis() ? 1 : 0];
            }
        }
        else
        {
            EECodeInfo codeInfo((PCODE)pData->Pc);
            pData->hiddenArg = EECodeManager::GetExactGenericsToken(
                (TADDR)(pData->probeSp), (TADDR)(pData->Fp), &codeInfo);
        }
    }
}

ProfileArgIterator::~ProfileArgIterator()
{
    LIMITED_METHOD_CONTRACT;

    m_handle = nullptr;
}

LPVOID ProfileArgIterator::CopyStructFromFPRegs(int firstFPReg, int numFPRegs, int hfaFieldSize)
{
    WRAPPER_NO_CONTRACT;

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(m_handle);
    if (hfaFieldSize == 8)
    {
        m_bufferPos = ALIGN_UP(m_bufferPos, 8);
    }

    BYTE*                           pDest = &pData->buffer[m_bufferPos];

    if (hfaFieldSize == 8)
    {
        UINT64* pSlots = reinterpret_cast<UINT64*>(pDest);
        for (int i = 0; i < numFPRegs; i++)
        {
            pSlots[i] = *(UINT64*)&pData->floatArgumentRegisters.f[firstFPReg + i];
        }

        m_bufferPos += numFPRegs * sizeof(UINT64);
        return pSlots;
    }

    _ASSERTE(hfaFieldSize == 4);

    float* pSlots = reinterpret_cast<float*>(pDest);
    for (int i = 0; i < numFPRegs; i++)
    {
        pSlots[i] = (float)pData->floatArgumentRegisters.f[firstFPReg + i];
    }

    m_bufferPos += numFPRegs * sizeof(float);
    return pSlots;
}

LPVOID ProfileArgIterator::CopyStructFromRegisters(const ArgLocDesc* sir)
{
    WRAPPER_NO_CONTRACT;

    _ASSERTE(m_handle != nullptr);

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(m_handle);

    if (sir->m_hfaFieldSize != 0)
    {
        return CopyStructFromFPRegs(sir->m_idxFloatReg, sir->m_cFloatReg, sir->m_hfaFieldSize);
    }

    if ((sir->m_cFloatReg == 0) && ((sir->m_cGenReg > 0) || (sir->m_byteStackSize > 0)))
    {
        _ASSERTE(sir->m_cGenReg > 0);
        _ASSERTE(sir->m_byteStackSize > 0);
        _ASSERTE(sir->m_byteStackIndex == 0);

        const int regBytes   = sir->m_cGenReg * TARGET_POINTER_SIZE;
        const int totalBytes = regBytes + sir->m_byteStackSize;
        m_bufferPos = ALIGN_UP(m_bufferPos, 8);
        _ASSERTE(m_bufferPos + totalBytes <= sizeof(pData->buffer));

        BYTE* dest = &pData->buffer[m_bufferPos];
        memcpyNoGCRefs(dest, &pData->argumentRegisters.r[sir->m_idxGenReg], regBytes);
        memcpyNoGCRefs(dest + regBytes, GetProfiledStackArg(pData, sir->m_byteStackIndex), sir->m_byteStackSize);
        m_bufferPos += totalBytes;
        return dest;
    }

    _ASSERTE(!"Unexpected PPC64LE struct-in-registers argument shape");
    return nullptr;
}

LPVOID ProfileArgIterator::GetNextArgAddr()
{
    WRAPPER_NO_CONTRACT;

    _ASSERTE(m_handle != nullptr);

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(m_handle);

    if ((pData->flags & (PROFILE_LEAVE | PROFILE_TAILCALL)) != 0)
    {
        _ASSERTE(!"GetNextArgAddr() - arguments are not available in leave and tailcall probes");
        return nullptr;
    }

    int argOffset = m_argIterator.GetNextOffset();
    if (argOffset == TransitionBlock::InvalidOffset)
    {
        return nullptr;
    }

    const ArgLocDesc* sir = m_argIterator.GetArgLocDescForStructInRegs();
    if (sir != nullptr)
    {
        return CopyStructFromRegisters(sir);
    }

    int argSize = m_argIterator.IsArgPassedByRef() ? (int)sizeof(void*) : m_argIterator.GetArgSize();
    if (TransitionBlock::IsFloatArgumentRegisterOffset(argOffset))
    {
        int offset = argOffset - TransitionBlock::GetOffsetOfFloatArgumentRegisters();
        _ASSERTE((offset >= 0) && (offset + (int)sizeof(double) <= (int)sizeof(pData->floatArgumentRegisters)));

        double* pReg = (double*)((LPBYTE)&pData->floatArgumentRegisters + offset);
        if (argSize == (int)sizeof(float))
        {
            _ASSERTE(m_bufferPos + sizeof(float) <= sizeof(pData->buffer));
            float* pFloat = (float*)&pData->buffer[m_bufferPos];
            *pFloat = (float)*pReg;
            m_bufferPos += sizeof(float);
            return pFloat;
        }

        return pReg;
    }

    LPVOID pArg = nullptr;
    if (TransitionBlock::IsArgumentRegisterOffset(argOffset))
    {
        int offset = argOffset - TransitionBlock::GetOffsetOfArgumentRegisters();
        if (offset + argSize > (int)sizeof(pData->argumentRegisters))
        {
            const int availableRegBytes = sizeof(pData->argumentRegisters) - offset;
            const int stackBytes        = argSize - availableRegBytes;
            _ASSERTE(availableRegBytes > 0);
            _ASSERTE(stackBytes > 0);
            _ASSERTE(m_bufferPos + argSize <= sizeof(pData->buffer));

            BYTE* dest = &pData->buffer[m_bufferPos];
            memcpyNoGCRefs(dest, (LPBYTE)&pData->argumentRegisters + offset, availableRegBytes);
            memcpyNoGCRefs(dest + availableRegBytes, GetProfiledStackArg(pData, 0), stackBytes);
            m_bufferPos += argSize;
            return dest;
        }

        pArg = (LPBYTE)&pData->argumentRegisters + offset;
    }
    else
    {
        _ASSERTE(TransitionBlock::IsStackArgumentOffset(argOffset));
        pArg = GetProfiledStackArg(pData, TransitionBlock::GetStackArgumentByteIndexFromOffset(argOffset));
    }

    if (m_argIterator.IsArgPassedByRef())
    {
        pArg = *(LPVOID*)pArg;
    }

    return pArg;
}

LPVOID ProfileArgIterator::GetHiddenArgValue(void)
{
    LIMITED_METHOD_CONTRACT;

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(m_handle);

    return pData->hiddenArg;
}

LPVOID ProfileArgIterator::GetThis(void)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = (PROFILE_PLATFORM_SPECIFIC_DATA*)m_handle;
    MethodDesc*                     pMD   = FunctionIdToMethodDesc(pData->functionId);

    if (pData->hiddenArg != nullptr)
    {
        if (pMD->AcquiresInstMethodTableFromThis())
        {
            return pData->hiddenArg;
        }
    }

    if ((pData->flags & PROFILE_ENTER) != 0)
    {
        if (m_argIterator.HasThis())
        {
            return (LPVOID)pData->argumentRegisters.r[0];
        }
    }

    return nullptr;
}

LPVOID ProfileArgIterator::GetReturnBufferAddr(void)
{
    CONTRACTL
    {
        NOTHROW;
        GC_NOTRIGGER;
    }
    CONTRACTL_END;

    PROFILE_PLATFORM_SPECIFIC_DATA* pData = reinterpret_cast<PROFILE_PLATFORM_SPECIFIC_DATA*>(m_handle);

    if ((pData->flags & PROFILE_TAILCALL) != 0)
    {
        _ASSERTE(!"GetReturnBufferAddr() - return buffer address is not available in tailcall probe");
        return nullptr;
    }

    if (m_argIterator.HasRetBuffArg())
    {
        _ASSERTE((pData->flags & PROFILE_LEAVE) != 0);
        return (LPVOID)pData->argumentRegisters.r[0];
    }

    const UINT fpReturnSize = m_argIterator.GetFPReturnSize();
    if (fpReturnSize != FpStruct::UseIntCallConv)
    {
        if ((fpReturnSize & Ppc64leHomogeneousAggregate::HomogeneousAggregate) != 0)
        {
            const UINT elemCount =
                (fpReturnSize & Ppc64leHomogeneousAggregate::ElementCountMask) >>
                Ppc64leHomogeneousAggregate::PosElementCount;
            const UINT elemSizeShift =
                (fpReturnSize & FpStruct::SizeShift1stMask) >> FpStruct::PosSizeShift1st;
            const UINT elemSize = 1u << elemSizeShift;
            return CopyStructFromFPRegs(0, elemCount, elemSize);
        }

        if (fpReturnSize & FpStruct::OnlyOne)
        {
            const UINT elemSizeShift = (fpReturnSize & FpStruct::SizeShift1stMask) >> FpStruct::PosSizeShift1st;
            const UINT elemSize      = 1u << elemSizeShift;
            if (elemSize == sizeof(float))
            {
                return CopyStructFromFPRegs(0, 1, sizeof(float));
            }

            _ASSERTE(elemSize == sizeof(double));
            return &pData->floatArgumentRegisters.f[0];
        }
    }

    if (!m_argIterator.GetSig()->IsReturnTypeVoid())
    {
        return &pData->argumentRegisters.r[0];
    }

    return nullptr;
}

#endif // PROFILING_SUPPORTED
