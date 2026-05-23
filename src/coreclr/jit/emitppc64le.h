// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if defined(TARGET_POWERPC64)

// PPC64LE instructions are 32 bits wide.
typedef unsigned int code_t;

struct CnsVal
{
    ssize_t cnsVal;
    bool    cnsReloc;
};

#ifdef DEBUG
const char* emitFPregName(unsigned reg, bool varName = true);
const char* emitVectorRegName(regNumber reg);
#endif // DEBUG

void emitIns_J(instruction ins, BasicBlock* dst, bool keepShort = false);

static bool isValidSimm16(ssize_t value)
{
    return (INT16_MIN <= value) && (value <= INT16_MAX);
}

static bool isValidSimm12(ssize_t value)
{
    return isValidSimm16(value);
}

inline static bool isGeneralRegister(regNumber reg)
{
    return (reg >= REG_INT_FIRST) && (reg <= REG_INT_LAST);
}

inline static bool isGeneralRegisterOrR0(regNumber reg)
{
    return isGeneralRegister(reg);
}

inline static bool isFloatReg(regNumber reg)
{
    return (reg >= REG_FP_FIRST) && (reg <= REG_FP_LAST);
}

void emitIns(instruction ins);
void emitIns_I(instruction ins, emitAttr attr, ssize_t imm);
void emitIns_R_I(instruction ins, emitAttr attr, regNumber reg, ssize_t imm, insOpts opt = INS_OPTS_NONE);
void emitIns_R_R(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, insOpts opt = INS_OPTS_NONE);
void emitIns_R_R(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, insFlags flags);
void emitIns_R_R_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, ssize_t imm, insOpts opt = INS_OPTS_NONE);
void emitIns_R_R_I_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, unsigned imm1, unsigned imm2);
void emitIns_R_R_I_I_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, unsigned imm1, unsigned imm2, unsigned imm3);
void emitIns_R_R_R(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, regNumber reg3, insOpts opt = INS_OPTS_NONE);
void emitIns_R_R_R_I(instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, regNumber reg3, ssize_t imm);
void emitIns_R_R_R_I_I(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, regNumber reg3, unsigned imm1, unsigned imm2);
void emitIns_R_L(instruction ins, emitAttr attr, BasicBlock* dst, regNumber reg);
void emitIns_R_L(instruction ins, emitAttr attr, insGroup* dst, regNumber reg);
void emitIns_R_L(instruction ins, emitAttr attr, insGroup* dst, regNumber reg, regNumber baseReg);
void emitIns_R_C(instruction ins, emitAttr attr, regNumber targetReg, regNumber addrReg, CORINFO_FIELD_HANDLE fldHnd);
void emitIns_R_S(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs);
void emitIns_R_S(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs, regNumber tmpReg);
void emitIns_R_S_I(
    instruction ins, emitAttr attr, regNumber ireg, int varx, int offs, int ival, insOpts opt = INS_OPTS_NONE);
void emitIns_S_R(instruction ins, emitAttr attr, regNumber ireg, int varx, int offs);
void emitIns_S_R_I(instruction ins, emitAttr attr, int varx, int offs, regNumber ireg, int ival);
void emitIns_R_AR(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, int offs);
void emitIns_AR_R(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, int offs);
void emitIns_R_ARR(instruction ins, emitAttr attr, regNumber ireg, regNumber reg, regNumber rg2, int disp);
void emitIns_Mov(
    instruction ins, emitAttr attr, regNumber dstReg, regNumber srcReg, bool canSkip, insOpts opt = INS_OPTS_NONE);
void emitIns_Mov(emitAttr attr, regNumber dstReg, regNumber srcReg, bool canSkip = false);

private:
instrDesc* emitNewInstrCallDir(int              argCnt,
                               VARSET_VALARG_TP GCvars,
                               regMaskTP        gcrefRegs,
                               regMaskTP        byrefRegs,
                               emitAttr retSize MULTIREG_HAS_SECOND_GC_RET_ONLY_ARG(emitAttr secondRetSize),
                               bool             hasAsyncRet);

instrDesc* emitNewInstrCallInd(int              argCnt,
                               ssize_t          disp,
                               VARSET_VALARG_TP GCvars,
                               regMaskTP        gcrefRegs,
                               regMaskTP        byrefRegs,
                               emitAttr retSize MULTIREG_HAS_SECOND_GC_RET_ONLY_ARG(emitAttr secondRetSize),
                               bool             hasAsyncRet);

private:
bool emitInsIsLoad(instruction ins);
bool emitInsIsStore(instruction ins);
bool emitInsIsLoadOrStore(instruction ins);

void emitDispInsName(code_t code, const instrDesc* id);
static emitter::code_t emitInsCode(instruction ins);
unsigned emitOutput_Instr(BYTE* dst, code_t code) const;
unsigned emitOutputLabelLoad(BYTE* dst, instrDesc* id);
unsigned emitOutputConstAddr(BYTE* dst, instrDesc* id);
unsigned emitOutputConstLoad(BYTE* dst, instrDesc* id);

void emitIns_Jump(instruction ins, BasicBlock* dst, bool keepShort = false);
void emitOutputInstrJumpDistanceHelper(const insGroup* ig,
                                       instrDescJmp*   jmp,
                                       UNATIVE_OFFSET& dstOffs,
                                       const BYTE*&    dstAddr) const;
ssize_t emitOutputInstrJumpDistance(const BYTE* src, const insGroup* ig, instrDescJmp* jmp);

inline static bool emitIsCmpJump(instruction ins)
{
    return (ins == INS_bc) || (ins == INS_blt) || (ins == INS_bge) || (ins == INS_bgt) || (ins == INS_ble) ||
           (ins == INS_beq) || (ins == INS_bne);
}

inline static bool emitIsCmpJump(instrDesc* jmp)
{
    return emitIsCmpJump(jmp->idIns());
}

inline static bool emitIsUncondJump(instruction ins)
{
    return (ins == INS_b) || (ins == INS_bl) || (ins == INS_bclr) || (ins == INS_blr) || (ins == INS_bctr);
}

inline static bool emitIsUncondJump(const instrDesc* jmp)
{
    return emitIsUncondJump(jmp->idIns());
}

#endif // TARGET_POWERPC64
