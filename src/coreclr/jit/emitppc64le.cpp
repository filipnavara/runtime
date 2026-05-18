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
            if (id->idIsLargeCall())
            {
                return sizeof(instrDescCGCA);
            }
            else
            {
                assert(!id->idIsLargeDsp());
                assert(!id->idIsLargeCns());
                return sizeof(instrDesc);
            }

        case INS_OPTS_NONE:
        case INS_OPTS_RC:
        case INS_OPTS_RL:
        case INS_OPTS_RELOC:
        case INS_OPTS_I:
            if (id->idIsLargeCns())
            {
                if (id->idIsLargeDsp())
                {
                    return sizeof(instrDescCnsDsp);
                }

                return sizeof(instrDescCns);
            }
            else if (id->idIsLargeDsp())
            {
                return sizeof(instrDescDsp);
            }

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
        case INS_stfd:
        case INS_stfs:
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
    *reinterpret_cast<code_t*>(dst + writeableOffset) = code;
    return sizeof(code_t);
}

static unsigned ppcReg(regNumber reg)
{
    assert((REG_R0 <= reg) && (reg <= REG_R31));
    return (unsigned)reg - (unsigned)REG_R0;
}

static unsigned ppcRegOrFReg(regNumber reg)
{
    if ((REG_R0 <= reg) && (reg <= REG_R31))
    {
        return (unsigned)reg - (unsigned)REG_R0;
    }

    assert((REG_F0 <= reg) && (reg <= REG_F31));
    return (unsigned)reg - (unsigned)REG_F0;
}

static unsigned ppcFReg(regNumber reg)
{
    assert((REG_F0 <= reg) && (reg <= REG_F31));
    return (unsigned)reg - (unsigned)REG_F0;
}

static emitter::code_t ppcEncodeDForm(emitter::code_t code, regNumber rt, regNumber ra, ssize_t imm)
{
    assert(emitter::isValidSimm16(imm));
    return code | (ppcRegOrFReg(rt) << 21) | (ppcReg(ra) << 16) | ((unsigned)imm & 0xFFFF);
}

static ssize_t ppcSignExtend16(uint64_t value)
{
    ssize_t part = static_cast<ssize_t>(value & 0xFFFF);
    return (part >= 0x8000) ? (part - 0x10000) : part;
}

static ssize_t ppcUnsigned16(uint64_t value)
{
    return static_cast<ssize_t>(value & 0xFFFF);
}

static emitter::code_t ppcEncodeXForm(emitter::code_t code, regNumber rt, regNumber ra, regNumber rb)
{
    return code | (ppcReg(rt) << 21) | (ppcReg(ra) << 16) | (ppcReg(rb) << 11);
}

static emitter::code_t ppcEncodeFpBinaryB(emitter::code_t code, regNumber frt, regNumber fra, regNumber frb)
{
    return code | (ppcFReg(frt) << 21) | (ppcFReg(fra) << 16) | (ppcFReg(frb) << 11);
}

static emitter::code_t ppcEncodeFpBinaryC(emitter::code_t code, regNumber frt, regNumber fra, regNumber frc)
{
    return code | (ppcFReg(frt) << 21) | (ppcFReg(fra) << 16) | (ppcFReg(frc) << 6);
}

static unsigned ppcSplit5_1(unsigned value)
{
    assert(value < 64);
    return ((value & 0x1F) << 1) | ((value >> 5) & 0x1);
}

static emitter::code_t ppcEncodeRldicl(emitter::code_t code, regNumber ra, regNumber rs, unsigned sh, unsigned mb)
{
    assert(sh < 64);
    assert(mb < 64);
    return code | (ppcReg(rs) << 21) | (ppcReg(ra) << 16) | ((sh & 0x1F) << 11) | (ppcSplit5_1(mb) << 5) |
           (((sh >> 5) & 0x1) << 1);
}

static emitter::code_t ppcEncodeSpr(unsigned spr)
{
    assert(spr < 1024);
    return ((spr & 0x1F) << 16) | ((spr >> 5) << 11);
}

static emitter::code_t ppcEncodeMfspr(emitter::code_t code, regNumber rt, unsigned spr)
{
    return code | (ppcReg(rt) << 21) | ppcEncodeSpr(spr);
}

static emitter::code_t ppcEncodeMtspr(emitter::code_t code, regNumber rs, unsigned spr)
{
    return code | (ppcReg(rs) << 21) | ppcEncodeSpr(spr);
}

static emitter::code_t ppcEncodeIFormBranch(emitter::code_t code, ssize_t dist)
{
    assert((dist & 0x3) == 0);
    assert((J_DIST_SMALL_MAX_NEG <= dist) && (dist <= J_DIST_SMALL_MAX_POS));
    return code | (static_cast<emitter::code_t>(dist) & 0x03FFFFFC);
}

static emitter::code_t ppcEncodeBFormBranch(emitter::code_t code, ssize_t dist)
{
    assert((dist & 0x3) == 0);
    assert((B_DIST_SMALL_MAX_NEG <= dist) && (dist <= B_DIST_SMALL_MAX_POS));
    return code | (static_cast<emitter::code_t>(dist) & 0x0000FFFC);
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
    instrDesc* id = emitNewInstrCns(attr, imm);

    id->idIns(ins);
    id->idInsOpt(INS_OPTS_I);
    id->idCodeSize(sizeof(code_t));

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_I(instruction ins, emitAttr attr, regNumber reg, ssize_t imm, insOpts opt)
{
    instrDesc* id = emitNewInstrCns(attr, imm);

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
    instrDesc* id = emitNewInstrCns(attr, imm);

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

void emitter::emitIns_R_C(
    instruction ins, emitAttr attr, regNumber targetReg, regNumber addrReg, CORINFO_FIELD_HANDLE fldHnd)
{
    assert(isFloatReg(targetReg) || isGeneralRegister(targetReg));

    const bool isAddressLoad = ins == INS_addi;
    assert(!EA_IS_RELOC(attr) || (isAddressLoad && m_compiler->opts.compReloc));
    if (isAddressLoad)
    {
        assert(EA_SIZE(attr) == EA_PTRSIZE);
        assert(isGeneralRegister(targetReg));
        assert(addrReg == REG_NA);
    }
    else
    {
        assert(emitInsIsLoad(ins));
        assert(isGeneralRegister(addrReg));
        assert(addrReg != REG_R0);
    }

    instrDesc* id = emitNewInstr(attr);
    id->idSetRelocFlags(attr);

    id->idIns(ins);
    id->idInsOpt(INS_OPTS_RC);
    id->idReg1(targetReg);
    id->idReg2(isAddressLoad ? REG_R0 : addrReg);
    id->idCodeSize((isAddressLoad ? (m_compiler->opts.compReloc ? 2 : 5) : (m_compiler->opts.compReloc ? 3 : 6)) *
                   sizeof(code_t));
    id->idSetIsBound();
    id->idAddr()->iiaFieldHnd = fldHnd;

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_L(instruction ins, emitAttr attr, BasicBlock* dst, regNumber reg)
{
    assert(dst->HasFlag(BBF_HAS_LABEL));
    assert(isGeneralRegister(reg));

    instrDesc* id = emitNewInstr(attr);

    id->idIns(ins);
    id->idInsOpt(INS_OPTS_RL);
    id->idAddr()->iiaBBlabel = dst;
    id->idCodeSize((m_compiler->opts.compReloc ? 2 : 5) * sizeof(code_t));
    id->idReg1(reg);

#ifdef DEBUG
    if (m_compiler->compCurBB->KindIs(BBJ_EHCATCHRET))
    {
        id->idDebugOnlyInfo()->idCatchRet = true;
    }
#endif // DEBUG

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_L(instruction ins, emitAttr attr, insGroup* dst, regNumber reg)
{
    assert(dst != nullptr);
    assert(isGeneralRegister(reg));

    instrDesc* id = emitNewInstr(attr);

    id->idIns(ins);
    id->idInsOpt(INS_OPTS_RL);
    id->idAddr()->iiaIGlabel = dst;
    id->idSetIsBound();
    id->idCodeSize((m_compiler->opts.compReloc ? 2 : 5) * sizeof(code_t));
    id->idReg1(reg);

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitIns_R_S(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs)
{
    ssize_t imm = offs;
    bool    FPbased = false;

    if (varx != BAD_VAR_NUM)
    {
        int base = m_compiler->lvaFrameAddress(varx, &FPbased);
        imm      = base + offs;
    }

    if (!isValidSimm16(imm))
    {
        NYI_POWERPC64("large stack local offset");
    }

    if (ins == INS_lea)
    {
        ins = INS_addi;
    }

    instrDesc* id = emitNewInstrCns(attr, imm);

    id->idIns(ins);
    id->idReg1(ireg);
    id->idReg2(FPbased ? REG_FPBASE : REG_SPBASE);
    id->idCodeSize(sizeof(code_t));

    if (varx != BAD_VAR_NUM)
    {
        id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);
        id->idSetIsLclVar();
    }

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
    ssize_t imm = offs;
    bool    FPbased = false;

    if (varx != BAD_VAR_NUM)
    {
        int base = m_compiler->lvaFrameAddress(varx, &FPbased);
        imm      = base + offs;
    }

    if (!isValidSimm16(imm))
    {
        NYI_POWERPC64("large stack local offset");
    }

    instrDesc* id = emitNewInstrCns(attr, imm);

    id->idIns(ins);
    id->idReg1(ireg);
    id->idReg2(FPbased ? REG_FPBASE : REG_SPBASE);
    id->idCodeSize(sizeof(code_t));

    if (varx != BAD_VAR_NUM)
    {
        id->idAddr()->iiaLclVar.initLclVarAddr(varx, offs);
        id->idSetIsLclVar();
    }

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
    if (ins == INS_lea)
    {
        if (!isValidSimm16(offs))
        {
            NYI_POWERPC64("large lea offset");
        }

        ins = INS_addi;
    }

    emitIns_R_R_I(ins, attr, ireg, reg, offs);
}

void emitter::emitIns_AR_R(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, int offs)
{
    emitIns_R_R_I(ins, attr, ireg, reg, offs);
}

void emitter::emitIns_R_ARR(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, regNumber rg2, int disp)
{
    if (ins == INS_lea)
    {
        emitIns_R_R_R(INS_add, attr, ireg, reg, rg2);

        if (disp != 0)
        {
            if (!isValidSimm16(disp))
            {
                NYI_POWERPC64("large indexed lea offset");
            }

            emitIns_R_R_I(INS_addi, attr, ireg, ireg, disp);
        }

        return;
    }

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

    if (isFloatReg(dstReg) || isFloatReg(srcReg))
    {
        assert(isFloatReg(dstReg));
        assert(isFloatReg(srcReg));
        ins = INS_fmr;
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
    BYTE*  dst      = *dp;
    size_t codeSize = id->idCodeSize();

    if (id->idInsOpt() == INS_OPTS_C)
    {
        codeSize = emitOutputCall(dst, id);
        *dp      = dst + codeSize;
        return emitSizeOfInsDsc(id);
    }

    if (id->idInsOpt() == INS_OPTS_RC)
    {
        codeSize = (id->idIns() == INS_addi) ? emitOutputConstAddr(dst, id) : emitOutputConstLoad(dst, id);
        *dp      = dst + codeSize;
        return emitSizeOfInsDsc(id);
    }

    if (id->idInsOpt() == INS_OPTS_RL)
    {
        if (!id->idIsBound())
        {
            insGroup* target = static_cast<insGroup*>(emitCodeGetCookie(id->idAddr()->iiaBBlabel));
            id->idAddr()->iiaIGlabel = target;
            id->idSetIsBound();
        }

        codeSize = emitOutputLabelLoad(dst, id);
        *dp      = dst + codeSize;
        return emitSizeOfInsDsc(id);
    }

    code_t code = emitInsCode(id->idIns());

    switch (id->idIns())
    {
        case INS_nop:
        case INS_trap:
        case INS_sync:
        case INS_bclr:
        case INS_blr:
        case INS_bctr:
        case INS_bctrl:
            break;

        case INS_mflr:
            code = ppcEncodeMfspr(code, id->idReg1(), 8);
            break;

        case INS_mtlr:
            code = ppcEncodeMtspr(code, id->idReg1(), 8);
            break;

        case INS_mtctr:
            code = ppcEncodeMtspr(code, id->idReg1(), 9);
            break;

        case INS_add:
        case INS_subf:
        case INS_mulhw:
        case INS_mulhwu:
        case INS_mullw:
        case INS_mulhd:
        case INS_mulhdu:
        case INS_mulld:
        case INS_divw:
        case INS_divd:
        case INS_divwu:
        case INS_divdu:
            code = ppcEncodeXForm(code, id->idReg1(), id->idReg2(), id->idReg3());
            break;

        case INS_and:
        case INS_andc:
        case INS_or:
        case INS_orc:
        case INS_xor:
        case INS_eqv:
        case INS_slw:
        case INS_sld:
        case INS_sraw:
        case INS_srad:
        case INS_srw:
        case INS_srd:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16) |
                   (ppcReg(id->idReg3()) << 11);
            break;

        case INS_extsb:
        case INS_extsh:
        case INS_extsw:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16);
            break;

        case INS_neg:
            code = code | (ppcReg(id->idReg1()) << 21) | (ppcReg(id->idReg2()) << 16);
            break;

        case INS_not:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16) |
                   (ppcReg(id->idReg2()) << 11);
            break;

        case INS_fmr:
        case INS_fneg:
        case INS_frsp:
        case INS_fctiwz:
        case INS_fctidz:
        case INS_fctiduz:
        case INS_fcfid:
        case INS_fcfids:
        case INS_fcfidu:
        case INS_fcfidus:
            code = code | (ppcFReg(id->idReg1()) << 21) | (ppcFReg(id->idReg2()) << 11);
            break;

        case INS_mffgpr:
            code = code | (ppcFReg(id->idReg1()) << 21) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_mftgpr:
            code = code | (ppcReg(id->idReg1()) << 21) | (ppcFReg(id->idReg2()) << 11);
            break;

        case INS_fadd:
        case INS_fadds:
        case INS_fsub:
        case INS_fsubs:
        case INS_fdiv:
        case INS_fdivs:
            code = ppcEncodeFpBinaryB(code, id->idReg1(), id->idReg2(), id->idReg3());
            break;

        case INS_fmul:
        case INS_fmuls:
            code = ppcEncodeFpBinaryC(code, id->idReg1(), id->idReg2(), id->idReg3());
            break;

        case INS_clrldi:
            code = ppcEncodeRldicl(code, id->idReg1(), id->idReg2(), 0, static_cast<unsigned>(emitGetInsSC(id)));
            break;

        case INS_sldi:
        {
            unsigned shift = static_cast<unsigned>(emitGetInsSC(id));
            assert(shift < 64);
            code = ppcEncodeRldicl(code, id->idReg1(), id->idReg2(), shift, 63 - shift);
            break;
        }

        case INS_mr:
        case INS_mov:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_addi:
        case INS_addis:
        case INS_ld:
        case INS_lwa:
        case INS_lwz:
        case INS_lhz:
        case INS_lbz:
        case INS_lfs:
        case INS_lfd:
        case INS_std:
        case INS_stw:
        case INS_sth:
        case INS_stb:
        case INS_stfs:
        case INS_stfd:
            code = ppcEncodeDForm(code, id->idReg1(), id->idReg2(), id->idIsCnsReloc() ? 0 : emitGetInsSC(id));
            break;

        case INS_ori:
        case INS_oris:
        case INS_xori:
            code = code | (ppcReg(id->idReg2()) << 21) | (ppcReg(id->idReg1()) << 16) |
                   ((unsigned)emitGetInsSC(id) & 0xFFFF);
            break;

        case INS_cmp:
        case INS_cmpd:
        case INS_cmpl:
        case INS_cmpld:
            code = code | (1u << 21) | (ppcReg(id->idReg1()) << 16) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_cmpw:
        case INS_cmplw:
            code = code | (ppcReg(id->idReg1()) << 16) | (ppcReg(id->idReg2()) << 11);
            break;

        case INS_fcmpu:
            code = code | (ppcFReg(id->idReg1()) << 16) | (ppcFReg(id->idReg2()) << 11);
            break;

        case INS_b:
        case INS_bl:
            if (id->idInsOpt() == INS_OPTS_JUMP)
            {
                code =
                    ppcEncodeIFormBranch(code, emitOutputInstrJumpDistance(dst, ig, static_cast<instrDescJmp*>(id)));
            }
            else if (id->idInsOpt() == INS_OPTS_I)
            {
                code = ppcEncodeIFormBranch(code, emitGetInsSC(id));
            }
            break;

        case INS_bc:
        case INS_blt:
        case INS_bge:
        case INS_bgt:
        case INS_ble:
        case INS_beq:
        case INS_bne:
            if (id->idInsOpt() == INS_OPTS_JUMP)
            {
                code =
                    ppcEncodeBFormBranch(code, emitOutputInstrJumpDistance(dst, ig, static_cast<instrDescJmp*>(id)));
            }
            else if (id->idInsOpt() == INS_OPTS_I)
            {
                code = ppcEncodeBFormBranch(code, emitGetInsSC(id));
            }
            break;

        default:
            code = emitInsCode(INS_trap);
            codeSize = sizeof(code_t);
            break;
    }

    emitOutput_Instr(dst, code);

    if (id->idIsCnsReloc())
    {
        CorInfoReloc relocType;
        switch (id->idIns())
        {
            case INS_addis:
                relocType = CorInfoReloc::PPC64_TOC16_HA;
                break;
            case INS_addi:
                relocType = CorInfoReloc::PPC64_TOC16_LO;
                break;
            default:
                unreached();
        }

        emitRecordRelocation(dst, reinterpret_cast<void*>(emitGetInsSC(id)), relocType);
    }

    *dp = dst + codeSize;
    return emitSizeOfInsDsc(id);
}

unsigned emitter::emitOutputLabelLoad(BYTE* dst, instrDesc* id)
{
    assert(id->idInsOpt() == INS_OPTS_RL);
    assert(id->idIsBound());
    assert(isGeneralRegister(id->idReg1()));

    const uintptr_t value = reinterpret_cast<uintptr_t>(emitCodeBlock + id->idAddr()->iiaIGlabel->igOffs);
    const regNumber reg  = id->idReg1();

    BYTE* cur = dst;

    if (m_compiler->opts.compReloc)
    {
        assert(id->idCodeSize() == 2 * sizeof(code_t));

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addis), reg, REG_R2, 0));
        emitRecordRelocation(cur, reinterpret_cast<void*>(value), CorInfoReloc::PPC64_TOC16_HA);
        cur += sizeof(code_t);

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addi), reg, reg, 0));
        emitRecordRelocation(cur, reinterpret_cast<void*>(value), CorInfoReloc::PPC64_TOC16_LO);
        cur += sizeof(code_t);

        return static_cast<unsigned>(cur - dst);
    }

    assert(id->idCodeSize() == 5 * sizeof(code_t));

    emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addis), reg, REG_R0, ppcSignExtend16(value >> 48)));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_ori) | (ppcReg(reg) << 21) | (ppcReg(reg) << 16) |
                         (ppcUnsigned16(value >> 32) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur, ppcEncodeRldicl(emitInsCode(INS_sldi), reg, reg, 32, 31));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_oris) | (ppcReg(reg) << 21) | (ppcReg(reg) << 16) |
                         (ppcUnsigned16(value >> 16) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_ori) | (ppcReg(reg) << 21) | (ppcReg(reg) << 16) |
                         (ppcUnsigned16(value) & 0xFFFF));
    cur += sizeof(code_t);

    return static_cast<unsigned>(cur - dst);
}

unsigned emitter::emitOutputConstAddr(BYTE* dst, instrDesc* id)
{
    assert(id->idInsOpt() == INS_OPTS_RC);
    assert(id->idIns() == INS_addi);
    assert(id->idAddr()->iiaIsJitDataOffset());
    assert(id->idGCref() == GCT_NONE);
    assert(isGeneralRegister(id->idReg1()));

    const int offset = id->idAddr()->iiaGetJitDataOffset();
    assert(offset >= 0);
    assert(static_cast<UNATIVE_OFFSET>(offset) < emitDataSize());

    const uintptr_t value = reinterpret_cast<uintptr_t>(emitDataOffsetToPtr(offset));
    const regNumber reg   = id->idReg1();

    BYTE* cur = dst;

    if (m_compiler->opts.compReloc)
    {
        assert(id->idCodeSize() == 2 * sizeof(code_t));

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addis), reg, REG_R2, 0));
        emitRecordRelocation(cur, reinterpret_cast<void*>(value), CorInfoReloc::PPC64_TOC16_HA);
        cur += sizeof(code_t);

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addi), reg, reg, 0));
        emitRecordRelocation(cur, reinterpret_cast<void*>(value), CorInfoReloc::PPC64_TOC16_LO);
        cur += sizeof(code_t);

        return static_cast<unsigned>(cur - dst);
    }

    assert(id->idCodeSize() == 5 * sizeof(code_t));

    emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addis), reg, REG_R0, ppcSignExtend16(value >> 48)));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_ori) | (ppcReg(reg) << 21) | (ppcReg(reg) << 16) |
                         (ppcUnsigned16(value >> 32) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur, ppcEncodeRldicl(emitInsCode(INS_sldi), reg, reg, 32, 31));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_oris) | (ppcReg(reg) << 21) | (ppcReg(reg) << 16) |
                         (ppcUnsigned16(value >> 16) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_ori) | (ppcReg(reg) << 21) | (ppcReg(reg) << 16) |
                         (ppcUnsigned16(value) & 0xFFFF));
    cur += sizeof(code_t);

    return static_cast<unsigned>(cur - dst);
}

unsigned emitter::emitOutputConstLoad(BYTE* dst, instrDesc* id)
{
    assert(id->idAddr()->iiaIsJitDataOffset());
    assert(id->idGCref() == GCT_NONE);
    assert(emitInsIsLoad(id->idIns()));

    const int offset = id->idAddr()->iiaGetJitDataOffset();
    assert(offset >= 0);
    assert(static_cast<UNATIVE_OFFSET>(offset) < emitDataSize());

    const uintptr_t addr    = reinterpret_cast<uintptr_t>(emitDataOffsetToPtr(offset));
    const uint64_t  value   = static_cast<uint64_t>(addr);
    regNumber       addrReg = id->idReg2();

    assert(isGeneralRegister(addrReg));
    assert(addrReg != REG_R0);

    BYTE* cur = dst;

    if (m_compiler->opts.compReloc)
    {
        assert(id->idCodeSize() == 3 * sizeof(code_t));

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addis), addrReg, REG_R2, 0));
        emitRecordRelocation(cur, reinterpret_cast<void*>(addr), CorInfoReloc::PPC64_TOC16_HA);
        cur += sizeof(code_t);

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addi), addrReg, addrReg, 0));
        emitRecordRelocation(cur, reinterpret_cast<void*>(addr), CorInfoReloc::PPC64_TOC16_LO);
        cur += sizeof(code_t);

        emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(id->idIns()), id->idReg1(), addrReg, 0));
        cur += sizeof(code_t);

        return static_cast<unsigned>(cur - dst);
    }

    assert(id->idCodeSize() == 6 * sizeof(code_t));

    emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(INS_addis), addrReg, REG_R0, ppcSignExtend16(value >> 48)));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_ori) | (ppcReg(addrReg) << 21) | (ppcReg(addrReg) << 16) |
                         (ppcUnsigned16(value >> 32) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur, ppcEncodeRldicl(emitInsCode(INS_sldi), addrReg, addrReg, 32, 31));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_oris) | (ppcReg(addrReg) << 21) | (ppcReg(addrReg) << 16) |
                         (ppcUnsigned16(value >> 16) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur,
                     emitInsCode(INS_ori) | (ppcReg(addrReg) << 21) | (ppcReg(addrReg) << 16) |
                         (ppcUnsigned16(value) & 0xFFFF));
    cur += sizeof(code_t);

    emitOutput_Instr(cur, ppcEncodeDForm(emitInsCode(id->idIns()), id->idReg1(), addrReg, 0));
    cur += sizeof(code_t);

    return static_cast<unsigned>(cur - dst);
}

void emitter::emitIns_J(instruction ins, BasicBlock* dst)
{
    assert(emitIsUncondJump(ins) || emitIsCmpJump(ins));
    emitIns_Jump(ins, dst);
}

void emitter::emitIns_Jump(instruction ins, BasicBlock* dst)
{
    assert(dst != nullptr);
    assert(dst->HasFlag(BBF_HAS_LABEL));
    assert(emitIsUncondJump(ins) || emitIsCmpJump(ins));

    instrDescJmp* id = emitNewInstrJmp();

    id->idIns(ins);
    id->idjShort = false;
    id->idCodeSize(sizeof(code_t));
    id->idInsOpt(INS_OPTS_JUMP);
    id->idAddr()->iiaBBlabel = dst;

#ifdef DEBUG
    if ((ins == INS_bl) && m_compiler->compCurBB->KindIs(BBJ_CALLFINALLY))
    {
        id->idDebugOnlyInfo()->idFinallyCall = true;
    }
#endif // DEBUG

    id->idjKeepLong = m_compiler->fgInDifferentRegions(m_compiler->compCurBB, dst);
#ifdef DEBUG
    if (m_compiler->opts.compLongAddress)
    {
        id->idjKeepLong = true;
    }
#endif // DEBUG

    id->idjIG   = emitCurIG;
    id->idjOffs = emitCurIGsize;

    id->idjNext      = emitCurIGjmpList;
    emitCurIGjmpList = id;

#if EMITTER_STATS
    emitTotalIGjmps++;
#endif // EMITTER_STATS

    insGroup* tgt = static_cast<insGroup*>(emitCodeGetCookie(dst));
    if (!id->idjKeepLong && (tgt != nullptr))
    {
        UNATIVE_OFFSET srcOffs = emitCurCodeOffset + emitCurIGsize;
        int            jmpDist = srcOffs - tgt->igOffs;
        assert(jmpDist >= 0);

        if (emitIsCmpJump(id))
        {
            if (B_DIST_SMALL_MAX_NEG <= -jmpDist)
            {
                emitSetShortJump(id);
            }
        }
        else if (J_DIST_SMALL_MAX_NEG <= -jmpDist)
        {
            emitSetShortJump(id);
        }
    }

    dispIns(id);
    appendToCurIG(id);
}

void emitter::emitOutputInstrJumpDistanceHelper(const insGroup* ig,
                                                instrDescJmp*   jmp,
                                                UNATIVE_OFFSET& dstOffs,
                                                const BYTE*&    dstAddr) const
{
    if (jmp->idAddr()->iiaHasInstrCount())
    {
        assert(ig != nullptr);
        int      instrCount = jmp->idAddr()->iiaGetInstrCount();
        unsigned insNum     = emitFindInsNum(ig, jmp);
        if (instrCount < 0)
        {
            assert(insNum + 1 >= static_cast<unsigned>(-instrCount));
        }
        dstOffs = ig->igOffs + emitFindOffset(ig, insNum + 1 + instrCount);
        dstAddr = emitOffsetToPtr(dstOffs);
        return;
    }

    assert(jmp->idIsBound());
    dstOffs = jmp->idAddr()->iiaIGlabel->igOffs;
    dstAddr = emitOffsetToPtr(dstOffs);
}

ssize_t emitter::emitOutputInstrJumpDistance(const BYTE* src, const insGroup* ig, instrDescJmp* jmp)
{
    UNATIVE_OFFSET srcOffs = emitCurCodeOffs(src);
    const BYTE*    srcAddr = emitOffsetToPtr(srcOffs);

    assert(!jmp->idAddr()->iiaIsJitDataOffset());

    UNATIVE_OFFSET dstOffs = 0;
    const BYTE*    dstAddr = nullptr;
    emitOutputInstrJumpDistanceHelper(ig, jmp, dstOffs, dstAddr);

    ssize_t distVal = static_cast<ssize_t>(dstAddr - srcAddr);

    if (dstOffs > srcOffs)
    {
        emitFwdJumps = true;

        if (!emitJumpCrossHotColdBoundary(srcOffs, dstOffs))
        {
            distVal -= emitOffsAdj;
            dstOffs -= emitOffsAdj;
        }

        jmp->idjOffs = dstOffs;
        if (jmp->idjOffs != dstOffs)
        {
            IMPL_LIMITATION("Method is too large");
        }
    }

    return distVal;
}

void emitter::emitIns_Call(const EmitCallParams& params)
{
    assert((params.callType == EC_INDIR_R) || (params.callType == EC_FUNC_TOKEN));
    assert((params.callType != EC_INDIR_R) || (isGeneralRegister(params.ireg) && (params.addr == nullptr)));
    assert((params.callType != EC_FUNC_TOKEN) || ((params.addr != nullptr) && (params.ireg == REG_NA)));

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

    if (params.retSize == EA_GCREF)
    {
        gcrefRegs |= RBM_INTRET;
    }
    else if (params.retSize == EA_BYREF)
    {
        byrefRegs |= RBM_INTRET;
    }

    if (params.secondRetSize == EA_GCREF)
    {
        gcrefRegs |= RBM_INTRET_1;
    }
    else if (params.secondRetSize == EA_BYREF)
    {
        byrefRegs |= RBM_INTRET_1;
    }

    VarSetOps::Assign(m_compiler, emitThisGCrefVars, params.ptrVars);
    emitThisGCrefRegs = gcrefRegs;
    emitThisByrefRegs = byrefRegs;

    id->idSetIsNoGC(params.isJump || params.noSafePoint || emitNoGChelper(params.methHnd));
    id->idIns(params.callType == EC_FUNC_TOKEN ? INS_bl : INS_bctrl);
    id->idInsOpt(INS_OPTS_C);
    if (params.callType == EC_FUNC_TOKEN)
    {
        assert(m_compiler->opts.compReloc);
        id->idAddr()->iiaAddr = static_cast<BYTE*>(params.addr);
        id->idCodeSize(2 * sizeof(code_t));
        id->idSetIsDspReloc();
    }
    else
    {
        id->idReg1(params.ireg);
        id->idCodeSize(2 * sizeof(code_t));
    }

    if (m_debugInfoSize > 0)
    {
        INDEBUG(id->idDebugOnlyInfo()->idCallSig = params.sigInfo);
        id->idDebugOnlyInfo()->idMemCookie = reinterpret_cast<size_t>(params.methHnd);
    }

    appendToCurIG(id);
}

unsigned emitter::emitOutputCall(BYTE* dst, instrDesc* id)
{
    regMaskTP gcrefRegs;
    regMaskTP byrefRegs;

    VARSET_TP GCvars(VarSetOps::UninitVal());

    if (id->idIsLargeCall())
    {
        instrDescCGCA* idCall = (instrDescCGCA*)id;
        gcrefRegs             = idCall->idcGcrefRegs;
        byrefRegs             = idCall->idcByrefRegs;
        VarSetOps::Assign(m_compiler, GCvars, idCall->idcGCvars);
    }
    else
    {
        assert(!id->idIsLargeDsp());
        assert(!id->idIsLargeCns());

        gcrefRegs = emitDecodeCallGCregs(id);
        byrefRegs = 0;
        VarSetOps::AssignNoCopy(m_compiler, GCvars, VarSetOps::MakeEmpty(m_compiler));
    }

    emitUpdateLiveGCvars(GCvars, dst);

#ifdef DEBUG
    if (EMIT_GC_VERBOSE || m_compiler->opts.disasmWithGC)
    {
        emitDispGCVarDelta();
    }
#endif

    if (id->idIsDspReloc())
    {
        assert(id->idIns() == INS_bl);
        emitOutput_Instr(dst, emitInsCode(INS_bl));
        emitRecordRelocation(dst, id->idAddr()->iiaAddr, CorInfoReloc::PPC64_REL24);
        emitOutput_Instr(dst + sizeof(code_t), emitInsCode(INS_nop));
    }
    else
    {
        emitOutput_Instr(dst, ppcEncodeMtspr(emitInsCode(INS_mtctr), id->idReg1(), 9));
        emitOutput_Instr(dst + sizeof(code_t), emitInsCode(INS_bctrl));
    }

    if (id->idGCref() == GCT_GCREF)
    {
        gcrefRegs |= RBM_INTRET;
    }
    else if (id->idGCref() == GCT_BYREF)
    {
        byrefRegs |= RBM_INTRET;
    }

    if (id->idIsLargeCall())
    {
        instrDescCGCA* idCall = (instrDescCGCA*)id;
#if MULTIREG_HAS_SECOND_GC_RET
        if (idCall->idSecondGCref() == GCT_GCREF)
        {
            gcrefRegs |= RBM_INTRET_1;
        }
        else if (idCall->idSecondGCref() == GCT_BYREF)
        {
            byrefRegs |= RBM_INTRET_1;
        }
#endif
        if (idCall->hasAsyncContinuationRet())
        {
            gcrefRegs |= RBM_ASYNC_CONTINUATION_RET;
        }
    }

    const unsigned callSize  = id->idCodeSize();
    BYTE*          callInstr = dst + callSize;

    if (gcrefRegs != emitThisGCrefRegs)
    {
        emitUpdateLiveGCregs(GCT_GCREF, gcrefRegs, callInstr);
    }
    if (byrefRegs != emitThisByrefRegs)
    {
        emitUpdateLiveGCregs(GCT_BYREF, byrefRegs, callInstr);
    }

    if (!id->idIsNoGC())
    {
        emitStackPop(callInstr, /* isCall */ true, sizeof(code_t), /* args */ 0);

        if (!emitFullGCinfo)
        {
            emitRecordGCcall(callInstr, sizeof(code_t));
        }
    }

#ifdef DEBUG
    if (EMIT_GC_VERBOSE || m_compiler->opts.disasmWithGC)
    {
        emitDispGCVarDelta();
    }
#endif

    return callSize;
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
