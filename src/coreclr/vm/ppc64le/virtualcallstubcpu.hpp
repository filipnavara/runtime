// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef _VIRTUAL_CALL_STUB_POWERPC64_H
#define _VIRTUAL_CALL_STUB_POWERPC64_H

#define USES_LOOKUP_STUBS 1

#define DISPATCH_STUB_FIRST_DWORD 0xe8030000 // ld r0,0(r3)
#define RESOLVE_STUB_FIRST_DWORD  0x3d800000 // addis r12,r0,imm16
#define VTABLECALL_STUB_FIRST_DWORD 0xe9630000 // ld r11,0(r3)
#define LOOKUP_STUB_FIRST_DWORD   0x3d800000 // addis r12,r0,imm16

struct Ppc64StubEmitter
{
    // These stubs run in the middle of managed calls. Preserve r10: it is the
    // last integer argument register on PPC64LE and can hold a real user arg.
    // r0 is safe as a raw scratch, but not as a D-form base register.
    static DWORD Addis(int rt, int ra, UINT16 imm)
    {
        LIMITED_METHOD_CONTRACT;
        return 0x3c000000u | (rt << 21) | (ra << 16) | imm;
    }

    static DWORD Ori(int ra, int rs, UINT16 imm)
    {
        LIMITED_METHOD_CONTRACT;
        return 0x60000000u | (rs << 21) | (ra << 16) | imm;
    }

    static DWORD Oris(int ra, int rs, UINT16 imm)
    {
        LIMITED_METHOD_CONTRACT;
        return 0x64000000u | (rs << 21) | (ra << 16) | imm;
    }

    static DWORD Ld(int rt, int offset, int ra)
    {
        LIMITED_METHOD_CONTRACT;
        _ASSERTE(FitsInI2(offset));
        return 0xe8000000u | (rt << 21) | (ra << 16) | (offset & 0xffff);
    }

    static DWORD LoadIndexed(int rt, int ra, int rb)
    {
        LIMITED_METHOD_CONTRACT;
        return 0x7c00002au | (rt << 21) | (ra << 16) | (rb << 11);
    }

    static DWORD Cmpd(int ra, int rb)
    {
        LIMITED_METHOD_CONTRACT;
        return 0x7c000000u | (ra << 16) | (rb << 11);
    }

    static DWORD Bne(int byteOffset)
    {
        LIMITED_METHOD_CONTRACT;
        _ASSERTE((byteOffset & 3) == 0);
        _ASSERTE(FitsInI2(byteOffset));
        return 0x40820000u | (byteOffset & 0xffff);
    }

    static void EmitLoadImm64(DWORD*& p, int reg, UINT64 value)
    {
        LIMITED_METHOD_CONTRACT;
        *p++ = Addis(reg, 0, static_cast<UINT16>(value >> 48));
        *p++ = Ori(reg, reg, static_cast<UINT16>(value >> 32));
        *p++ = 0x780007c6u | (reg << 21) | (reg << 16);
        *p++ = Oris(reg, reg, static_cast<UINT16>(value >> 16));
        *p++ = Ori(reg, reg, static_cast<UINT16>(value));
    }

    static void EmitTailBranchRegister(DWORD*& p, int reg)
    {
        LIMITED_METHOD_CONTRACT;
        *p++ = 0x7c0903a6u | (reg << 21); // mtctr reg
        *p++ = 0x4e800420u;               // bctr
    }

    static void EmitMoveRegister(DWORD*& p, int rd, int rs)
    {
        LIMITED_METHOD_CONTRACT;
        *p++ = 0x7c000378u | (rs << 21) | (rd << 16) | (rs << 11); // mr rd, rs
    }
};

struct LookupStub
{
    inline PCODE entryPoint() { LIMITED_METHOD_CONTRACT; return (PCODE)&_entryPoint[0]; }
    inline size_t token() { LIMITED_METHOD_CONTRACT; return _token; }
    inline size_t size() { LIMITED_METHOD_CONTRACT; return sizeof(LookupStub); }

private:
    friend struct LookupHolder;

    DWORD _entryPoint[10];
    PCODE _resolveWorkerTarget;
    size_t _token;
};

struct LookupHolder
{
private:
    LookupStub _stub;

public:
    static void InitializeStatic() { }

    void Initialize(LookupHolder* pLookupHolderRX, PCODE resolveWorkerTarget, size_t dispatchToken)
    {
        DWORD* p = _stub._entryPoint;
        Ppc64StubEmitter::EmitLoadImm64(p, 12, reinterpret_cast<UINT64>(&pLookupHolderRX->_stub));
        *p++ = Ppc64StubEmitter::Ld(0, offsetof(LookupStub, _token), 12);
        *p++ = Ppc64StubEmitter::Ld(12, offsetof(LookupStub, _resolveWorkerTarget), 12);
        *p++ = 0x7c0903a6u | (12 << 21); // mtctr r12
        Ppc64StubEmitter::EmitMoveRegister(p, 12, 0);
        *p++ = 0x4e800420u; // bctr
        _ASSERTE(p == &_stub._entryPoint[ARRAY_SIZE(_stub._entryPoint)]);

        _stub._resolveWorkerTarget = resolveWorkerTarget;
        _stub._token = dispatchToken;
    }

    LookupStub* stub() { LIMITED_METHOD_CONTRACT; return &_stub; }

    static LookupHolder* FromLookupEntry(PCODE lookupEntry)
    {
        return (LookupHolder*)(lookupEntry - offsetof(LookupHolder, _stub) - offsetof(LookupStub, _entryPoint));
    }
};

struct DispatchStub
{
    inline PCODE entryPoint() { LIMITED_METHOD_CONTRACT; return (PCODE)&_entryPoint[0]; }

    inline size_t expectedMT() { LIMITED_METHOD_CONTRACT; return _expectedMT; }
    inline PCODE implTarget() { LIMITED_METHOD_CONTRACT; return _implTarget; }

    inline TADDR implTargetSlot(EntryPointSlots::SlotType* slotTypeRef) const
    {
        LIMITED_METHOD_CONTRACT;
        _ASSERTE(slotTypeRef != nullptr);

        *slotTypeRef = EntryPointSlots::SlotType_Executable;
        return (TADDR)&_implTarget;
    }

    inline PCODE failTarget() { LIMITED_METHOD_CONTRACT; return _failTarget; }
    inline size_t size() { LIMITED_METHOD_CONTRACT; return sizeof(DispatchStub); }

private:
    friend struct DispatchHolder;

    DWORD _entryPoint[25];
    size_t _expectedMT;
    PCODE _implTarget;
    PCODE _failTarget;
};

struct DispatchHolder
{
    static void InitializeStatic()
    {
        LIMITED_METHOD_CONTRACT;
        static_assert(((offsetof(DispatchHolder, _stub) + offsetof(DispatchStub, _implTarget)) % sizeof(void*)) == 0);
    }

    void Initialize(DispatchHolder* pDispatchHolderRX, PCODE implTarget, PCODE failTarget, size_t expectedMT)
    {
        DWORD* p = _stub._entryPoint;
        Ppc64StubEmitter::EmitLoadImm64(p, 12, reinterpret_cast<UINT64>(&pDispatchHolderRX->_stub));
        *p++ = Ppc64StubEmitter::Ld(0, 0, 3);
        *p++ = Ppc64StubEmitter::Ld(12, offsetof(DispatchStub, _expectedMT), 12);
        *p++ = Ppc64StubEmitter::Cmpd(0, 12);
        *p++ = Ppc64StubEmitter::Bne(36);
        Ppc64StubEmitter::EmitLoadImm64(p, 12, reinterpret_cast<UINT64>(&pDispatchHolderRX->_stub));
        *p++ = Ppc64StubEmitter::Ld(12, offsetof(DispatchStub, _implTarget), 12);
        Ppc64StubEmitter::EmitTailBranchRegister(p, 12);
        Ppc64StubEmitter::EmitLoadImm64(p, 12, reinterpret_cast<UINT64>(&pDispatchHolderRX->_stub));
        *p++ = Ppc64StubEmitter::Ld(12, offsetof(DispatchStub, _failTarget), 12);
        Ppc64StubEmitter::EmitTailBranchRegister(p, 12);
        _ASSERTE(p == &_stub._entryPoint[ARRAY_SIZE(_stub._entryPoint)]);

        _stub._expectedMT = expectedMT;
        _stub._implTarget = implTarget;
        _stub._failTarget = failTarget;
    }

    DispatchStub* stub() { LIMITED_METHOD_CONTRACT; return &_stub; }

    static DispatchHolder* FromDispatchEntry(PCODE dispatchEntry)
    {
        LIMITED_METHOD_CONTRACT;
        return (DispatchHolder*)(dispatchEntry - offsetof(DispatchHolder, _stub) - offsetof(DispatchStub, _entryPoint));
    }

private:
    DispatchStub _stub;
};

struct ResolveStub
{
    inline PCODE failEntryPoint() { LIMITED_METHOD_CONTRACT; return (PCODE)&_failEntryPoint[0]; }
    inline PCODE resolveEntryPoint() { LIMITED_METHOD_CONTRACT; return (PCODE)&_resolveEntryPoint[0]; }
    inline PCODE slowEntryPoint() { LIMITED_METHOD_CONTRACT; return (PCODE)&_slowEntryPoint[0]; }
    inline size_t token() { LIMITED_METHOD_CONTRACT; return _token; }
    inline INT32* pCounter() { LIMITED_METHOD_CONTRACT; return _pCounter; }

    inline UINT32 hashedToken() { LIMITED_METHOD_CONTRACT; return _hashedToken >> LOG2_PTRSIZE; }
    inline size_t cacheAddress() { LIMITED_METHOD_CONTRACT; return _cacheAddress; }
    inline size_t size() { LIMITED_METHOD_CONTRACT; return sizeof(ResolveStub); }

private:
    friend struct ResolveHolder;

    DWORD _resolveEntryPoint[10];
    DWORD _slowEntryPoint[10];
    DWORD _failEntryPoint[11];
    UINT32 _hashedToken;
    INT32* _pCounter;
    size_t _cacheAddress;
    size_t _token;
    PCODE _resolveWorkerTarget;
};

struct ResolveHolder
{
    static void InitializeStatic() { }

    void Initialize(ResolveHolder* pResolveHolderRX,
                    PCODE resolveWorkerTarget,
                    PCODE patcherTarget,
                    size_t dispatchToken,
                    UINT32 hashedToken,
                    void* cacheAddr,
                    INT32* counterAddr)
    {
        auto emitSlowPath = [](DWORD*& p, ResolveStub* pStubRX) {
            Ppc64StubEmitter::EmitLoadImm64(p, 12, reinterpret_cast<UINT64>(pStubRX));
            *p++ = Ppc64StubEmitter::Ld(0, offsetof(ResolveStub, _token), 12);
            *p++ = Ppc64StubEmitter::Ld(12, offsetof(ResolveStub, _resolveWorkerTarget), 12);
            *p++ = 0x7c0903a6u | (12 << 21); // mtctr r12
            Ppc64StubEmitter::EmitMoveRegister(p, 12, 0);
            *p++ = 0x4e800420u; // bctr
        };

        DWORD* p = _stub._resolveEntryPoint;
        emitSlowPath(p, &pResolveHolderRX->_stub);
        _ASSERTE(p == &_stub._resolveEntryPoint[ARRAY_SIZE(_stub._resolveEntryPoint)]);

        p = _stub._slowEntryPoint;
        emitSlowPath(p, &pResolveHolderRX->_stub);
        _ASSERTE(p == &_stub._slowEntryPoint[ARRAY_SIZE(_stub._slowEntryPoint)]);

        p = _stub._failEntryPoint;
        _ASSERTE(SDF_ResolveBackPatch == 0x1);
        *p++ = Ppc64StubEmitter::Ori(11, 11, SDF_ResolveBackPatch);
        emitSlowPath(p, &pResolveHolderRX->_stub);
        _ASSERTE(p == &_stub._failEntryPoint[ARRAY_SIZE(_stub._failEntryPoint)]);

        _stub._hashedToken = hashedToken << LOG2_PTRSIZE;
        _stub._pCounter = counterAddr;
        _stub._cacheAddress = reinterpret_cast<size_t>(cacheAddr);
        _stub._token = dispatchToken;
        _stub._resolveWorkerTarget = resolveWorkerTarget;

        _ASSERTE(patcherTarget == (PCODE)NULL);
#ifdef CHAIN_LOOKUP
        _ASSERTE(resolveWorkerTarget == (PCODE)ResolveWorkerChainLookupAsmStub);
#else
        _ASSERTE(resolveWorkerTarget == (PCODE)ResolveWorkerAsmStub);
#endif
    }

    ResolveStub* stub() { LIMITED_METHOD_CONTRACT; return &_stub; }

    static ResolveHolder* FromFailEntry(PCODE failEntry);
    static ResolveHolder* FromResolveEntry(PCODE resolveEntry);

private:
    ResolveStub _stub;
};

struct VTableCallStub
{
    friend struct VTableCallHolder;

    inline size_t size()
    {
        LIMITED_METHOD_CONTRACT;
        return (5 + 2 + 2 + 2 + 1) * sizeof(DWORD);
    }

    inline PCODE entryPoint() const { LIMITED_METHOD_CONTRACT; return (PCODE)&_entryPoint[0]; }

    inline size_t token()
    {
        LIMITED_METHOD_CONTRACT;
        DWORD slot = *(DWORD*)(reinterpret_cast<BYTE*>(this) + size() - 4);
        return DispatchToken::CreateDispatchToken(slot).To_SIZE_T();
    }

private:
    BYTE _entryPoint[0];
};

struct VTableCallHolder
{
    void Initialize(unsigned slot);

    VTableCallStub* stub() { LIMITED_METHOD_CONTRACT; return reinterpret_cast<VTableCallStub*>(this); }

    static size_t GetHolderSize(unsigned slot)
    {
        STATIC_CONTRACT_WRAPPER;
        return (5 + 2 + 2 + 2 + 1) * sizeof(DWORD);
    }

    static VTableCallHolder* FromVTableCallEntry(PCODE entry)
    {
        LIMITED_METHOD_CONTRACT;
        return (VTableCallHolder*)entry;
    }
};

#ifdef DECLARE_DATA
#ifndef DACCESS_COMPILE

ResolveHolder* ResolveHolder::FromFailEntry(PCODE failEntry)
{
    LIMITED_METHOD_CONTRACT;
    return (ResolveHolder*)(failEntry - offsetof(ResolveHolder, _stub) - offsetof(ResolveStub, _failEntryPoint));
}

ResolveHolder* ResolveHolder::FromResolveEntry(PCODE resolveEntry)
{
    LIMITED_METHOD_CONTRACT;
    return (ResolveHolder*)(resolveEntry - offsetof(ResolveHolder, _stub) - offsetof(ResolveStub, _resolveEntryPoint));
}

void VTableCallHolder::Initialize(unsigned slot)
{
    unsigned offsetOfIndirection =
        MethodTable::GetVtableOffset() + MethodTable::GetIndexOfVtableIndirection(slot) * TARGET_POINTER_SIZE;
    unsigned offsetAfterIndirection = MethodTable::GetIndexAfterVtableIndirection(slot) * TARGET_POINTER_SIZE;

    DWORD* p = reinterpret_cast<DWORD*>(stub()->entryPoint());

    *p++ = Ppc64StubEmitter::Ld(11, 0, 3);
    if (FitsInI2(offsetOfIndirection))
    {
        *p++ = Ppc64StubEmitter::Ld(11, offsetOfIndirection, 11);
    }
    else
    {
        Ppc64StubEmitter::EmitLoadImm64(p, 12, offsetOfIndirection);
        *p++ = Ppc64StubEmitter::LoadIndexed(11, 11, 12);
    }

    if (FitsInI2(offsetAfterIndirection))
    {
        *p++ = Ppc64StubEmitter::Ld(11, offsetAfterIndirection, 11);
    }
    else
    {
        Ppc64StubEmitter::EmitLoadImm64(p, 12, offsetAfterIndirection);
        *p++ = Ppc64StubEmitter::LoadIndexed(11, 11, 12);
    }

    Ppc64StubEmitter::EmitTailBranchRegister(p, 11);
    while (p < (DWORD*)((BYTE*)stub()->entryPoint() + VTableCallHolder::GetHolderSize(slot) - sizeof(DWORD)))
    {
        *p++ = 0;
    }
    *p++ = slot;

    _ASSERT(p == (DWORD*)((BYTE*)stub()->entryPoint() + VTableCallHolder::GetHolderSize(slot)));
}

#endif // DACCESS_COMPILE
#endif // DECLARE_DATA

#endif // _VIRTUAL_CALL_STUB_POWERPC64_H
