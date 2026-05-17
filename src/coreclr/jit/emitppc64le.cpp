// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

#if defined(TARGET_POWERPC64)

#include "instr.h"
#include "emit.h"
#include "codegen.h"

const instruction emitJumpKindInstructions[] = {
    INS_nop,

#define JMP_SMALL(en, rev, ins) INS_##ins,
#include "emitjmps.h"
};

const emitJumpKind emitReverseJumpKinds[] = {
    EJ_NONE,

#define JMP_SMALL(en, rev, ins) EJ_##rev,
#include "emitjmps.h"
};

/*static*/ instruction emitter::emitJumpKindToIns(emitJumpKind jumpKind)
{
    assert((unsigned)jumpKind < ArrLen(emitJumpKindInstructions));
    return emitJumpKindInstructions[jumpKind];
}

/*static*/ emitJumpKind emitter::emitReverseJumpKind(emitJumpKind jumpKind)
{
    assert(jumpKind < EJ_COUNT);
    return emitReverseJumpKinds[jumpKind];
}

size_t emitter::emitSizeOfInsDsc(instrDesc* id) const
{
    if (emitIsSmallInsDsc(id))
    {
        return SMALL_IDSC_SIZE;
    }

    switch (id->idInsOpt())
    {
        case INS_OPTS_JUMP:
            return sizeof(instrDescJmp);

        case INS_OPTS_C:
            return id->idIsLargeCall() ? sizeof(instrDescCGCA) : sizeof(instrDesc);

        case INS_OPTS_NONE:
        case INS_OPTS_RC:
        case INS_OPTS_RL:
        case INS_OPTS_RELOC:
        case INS_OPTS_I:
            return sizeof(instrDesc);

        default:
            NO_WAY("unexpected instruction descriptor format");
    }
}

#ifdef DEBUG
void emitter::emitInsSanityCheck(instrDesc* id)
{
}
#endif // DEBUG

bool emitter::emitInsWritesToLclVarStackLoc(instrDesc* id)
{
    if (!id->idIsLclVar())
    {
        return false;
    }

    switch (id->idIns())
    {
        case INS_std:
        case INS_stw:
        case INS_sth:
        case INS_stb:
            return true;

        default:
            return false;
    }
}

#define LD 1
#define ST 2

// clang-format off
/*static*/ const BYTE CodeGenInterface::instInfo[] =
{
    #define INST(id, nm, info, e1) info,
    #include "instrs.h"
};
// clang-format on

bool emitter::emitInsIsLoad(instruction ins)
{
    return (ins < ArrLen(CodeGenInterface::instInfo)) && ((CodeGenInterface::instInfo[ins] & LD) != 0);
}

bool emitter::emitInsIsStore(instruction ins)
{
    return (ins < ArrLen(CodeGenInterface::instInfo)) && ((CodeGenInterface::instInfo[ins] & ST) != 0);
}

bool emitter::emitInsIsLoadOrStore(instruction ins)
{
    return emitInsIsLoad(ins) || emitInsIsStore(ins);
}

bool emitter::emitInsMayWriteToGCReg(instruction ins)
{
    return !emitInsIsStore(ins) && (ins != INS_nop) && (ins != INS_trap);
}

/*static*/ emitter::code_t emitter::emitInsCode(instruction ins)
{
    static const code_t code[] = {
#define INST(id, nm, info, e1) e1,
#include "instrs.h"
    };

    assert((unsigned)ins < ArrLen(code));
    return code[ins];
}

unsigned emitter::emitOutput_Instr(BYTE* dst, code_t code) const
{
    assert((reinterpret_cast<uintptr_t>(dst) % sizeof(code_t)) == 0);
    *reinterpret_cast<code_t*>(dst) = code;
    return sizeof(code_t);
}

static unsigned ppcReg(regNumber reg)
{
    assert((REG_R0 <= reg) && (reg <= REG_R31));
    return (unsigned)reg - (unsigned)REG_R0;
}

static emitter::code_t ppcEncodeDForm(emitter::code_t code, regNumber rt, regNumber ra, ssize_t imm)
{
    assert(emitter::isValidSimm16(imm));
    return code | (ppcReg(rt) << 21) | (ppcReg(ra) << 16) | ((unsigned)imm & 0xFFFF);
}

static emitter::code_t ppcEncodeXForm(emitter::code_t code, regNumber rt, regNumber ra, regNumber rb)
{
    return code | (ppcReg(rt) << 21) | (ppcReg(ra) << 16) | (ppcReg(rb) << 11);
}

void emitter::emitIns(instruction ins)
{
    instrDesc* id = emitNewInstr(EA_4BYTE);

    id->idIns(ins);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_I(instruction ins, emitAttr attr, ssize_t imm)
{
    instrDesc* id = emitNewInstrSC(attr, imm);

    id->idIns(ins);
    id->idInsOpt(INS_OPTS_I);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_I(instruction ins, emitAttr attr, regNumber reg, ssize_t imm, insOpts opt)
{
    instrDesc* id = emitNewInstrSC(attr, imm);

    id->idIns(ins);
    id->idInsOpt(opt);
    id->idReg1(reg);
    id->idReg2(REG_R0);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_R(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, insOpts opt)
{
    (void)reg1;
    (void)reg2;
    (void)opt;
    instrDesc* id = emitNewInstr(attr);

    id->idIns(ins);
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_R(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, insFlags flags)
{
    (void)flags;
    emitIns_R_R(ins, attr, reg1, reg2);
}

void emitter::emitIns_R_R_I(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, ssize_t imm, insOpts opt)
{
    instrDesc* id = emitNewInstrSC(attr, imm);

    id->idIns(ins);
    id->idInsOpt(opt);
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_R_R(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, regNumber reg3, insOpts opt)
{
    instrDesc* id = emitNewInstr(attr);

    id->idIns(ins);
    id->idInsOpt(opt);
    id->idReg1(reg1);
    id->idReg2(reg2);
    id->idReg3(reg3);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_S(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs)
{
    (void)varx;
    instrDesc* id = emitNewInstrSC(attr, offs);

    id->idIns(ins);
    id->idReg1(ireg);
    id->idReg2(REG_SPBASE);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_S_I(
    instruction ins, emitAttr attr, regNumber ireg, int varx, int offs, int ival, insOpts opt)
{
    (void)ival;
    (void)opt;
    emitIns_R_S(ins, attr, ireg, varx, offs);
}

void emitter::emitIns_S_R(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs)
{
    (void)varx;
    instrDesc* id = emitNewInstrSC(attr, offs);

    id->idIns(ins);
    id->idReg1(ireg);
    id->idReg2(REG_SPBASE);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_S_R_I(instruction ins, emitAttr attr, int varx, int offs, regNumber ireg, int ival)
{
    (void)ival;
    emitIns_S_R(ins, attr, ireg, varx, offs);
}

void emitter::emitIns_R_AR(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, int offs)
{
    emitIns_R_R_I(ins, attr, ireg, reg, offs);
}

void emitter::emitIns_AR_R(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, int offs)
{
    emitIns_R_R_I(ins, attr, ireg, reg, offs);
}

void emitter::emitIns_R_ARR(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, regNumber rg2, int disp)
{
    (void)reg;
    (void)rg2;
    emitIns_R_S(ins, attr, ireg, BAD_VAR_NUM, disp);
}

void emitter::emitIns_Mov(
    instruction ins, emitAttr attr, regNumber dstReg, regNumber srcReg, bool canSkip, insOpts opt)
{
    if (canSkip && (dstReg == srcReg))
    {
        return;
    }

    emitIns_R_R(ins, attr, dstReg, srcReg, opt);
}

void emitter::emitIns_Mov(emitAttr attr, regNumber dstReg, regNumber srcReg, bool canSkip)
{
    emitIns_Mov(INS_mov, attr, dstReg, srcReg, canSkip);
}

emitter::instrDesc* emitter::emitNewInstrLoadImm(emitAttr attr, cnsval_ssize_t cns)
{
    (void)cns;
    instrDesc* id = emitNewInstr(attr);
    id->idCodeSize(sizeof(code_t));
    return id;
}

size_t emitter::emitOutputInstr(insGroup* ig, instrDesc* id, BYTE** dp)
{
    BYTE*  dst  = *dp;
    size_t size = id->idCodeSize();
    code_t code = emitInsCode(id->idIns());

    switch (id->idIns())
    {
        case INS_nop:
        case INS_trap:
        case INS_bclr:
        case INS_blr:
            break;

        case INS_add:
            code = ppcEncodeXForm(code, id->idReg1(), id->idReg2(), id->idReg3());
            break;

        case INS_mr:
        case INS_mov:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_addi:
        case INS_addis:
        case INS_ld:
        case INS_lwz:
        case INS_lhz:
        case INS_lbz:
        case INS_std:
        case INS_stw:
        case INS_sth:
        case INS_stb:
            code = ppcEncodeDForm(code, id->idReg1(), id->idReg2(), emitGetInsSC(id));
            break;

        case INS_ori:
        case INS_oris:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16) |
                   ((unsigned)emitGetInsSC(id) & 0xFFFF);
            break;

        case INS_cmp:
        case INS_cmpd:
            code = code | (1u << 21) | (ppcReg(id->idReg1()) << 16) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_cmpw:
            code = code | (ppcReg(id->idReg1()) << 16) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_b:
        case INS_bl:
        case INS_bc:
        case INS_beq:
        case INS_bne:
            // Branch displacement binding is still skeletal; keep offset zero for now.
            break;

        default:
            code = emitInsCode(INS_trap);
            size = sizeof(code_t);
            break;
    }

    emitOutput_Instr(dst, code);

    *dp = dst + size;
    return size;
}

void emitter::emitIns_J(instruction ins, BasicBlock* dst)
{
    NYI_POWERPC64("emitIns_J");
}

void emitter::emitIns_Call(const EmitCallParams& params)
{
    regMaskTP savedSet  = emitGetGCRegsSavedOrModified(params.methHnd);
    regMaskTP gcrefRegs = params.gcrefRegs & savedSet;
    regMaskTP byrefRegs = params.byrefRegs & savedSet;

    assert(params.argSize % REGSIZE_BYTES == 0);
    const int argCnt = (int)(params.argSize / (int)REGSIZE_BYTES);

    instrDesc* id;
    if (params.callType >= EC_INDIR_R)
    {
        id = emitNewInstrCallInd(argCnt, params.disp, params.ptrVars, gcrefRegs, byrefRegs, params.retSize
                                      MULTIREG_HAS_SECOND_GC_RET_ONLY_ARG(params.secondRetSize),
                                  params.hasAsyncRet);
    }
    else
    {
        id = emitNewInstrCallDir(argCnt, params.ptrVars, gcrefRegs, byrefRegs,
                                 params.retSize MULTIREG_HAS_SECOND_GC_RET_ONLY_ARG(params.secondRetSize),
                                 params.hasAsyncRet);
    }

    id->idIns(INS_bl);
    id->idCodeSize(sizeof(code_t));
    appendToCurIG(id);
}

void emitter::emitSetShortJump(instrDescJmp* id)
{
    if (id->idjKeepLong)
    {
        return;
    }

    id->idCodeSize(sizeof(code_t));
    id->idjShort = true;
}

bool emitter::emitIsFuncEnd(emitLocation* emitLoc, emitLocation* emitLocNextFragment)
{
    assert(emitLoc != nullptr);
    insGroup* ig = emitLoc->GetIG();
    return (ig == nullptr) || (ig->igNext == nullptr) ||
           ((emitLocNextFragment != nullptr) && (ig->igNext == emitLocNextFragment->GetIG()));
}

void emitter::emitSplit(emitLocation*         startLoc,
                        emitLocation*         endLoc,
                        UNATIVE_OFFSET        maxSplitSize,
                        void*                 context,
                        emitSplitCallbackType callbackFunc)
{
}

void emitter::emitUnwindNopPadding(emitLocation* locFrom, Compiler* comp)
{
}

#if defined(DEBUG) || defined(LATE_DISASM)
emitter::insExecutionCharacteristics emitter::getInsExecutionCharacteristics(instrDesc* id)
{
    insExecutionCharacteristics result;
    result.insThroughput = PERFSCORE_THROUGHPUT_1C;
    result.insLatency    = PERFSCORE_LATENCY_1C;
    return result;
}
#endif // defined(DEBUG) || defined(LATE_DISASM)

const char* emitter::emitRegName(regNumber reg, emitAttr size, bool varName) const
{
    return getRegName(reg);
}

void emitter::emitDispIns(
    instrDesc* id, bool isNew, bool doffs, bool asmfm, unsigned offs, BYTE* pCode, size_t sz, insGroup* ig)
{
}

#endif // TARGET_POWERPC64
