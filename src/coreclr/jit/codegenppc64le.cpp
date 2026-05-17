// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

#if defined(TARGET_POWERPC64)

#include "codegen.h"
#include "lower.h"
#include "gcinfo.h"

static instruction ppcCompareInsForCondition(GenCondition cond, emitAttr cmpSize)
{
    assert((cmpSize == EA_4BYTE) || (cmpSize == EA_8BYTE));
    return cond.IsUnsigned() ? ((cmpSize == EA_4BYTE) ? INS_cmplw : INS_cmpld)
                             : ((cmpSize == EA_4BYTE) ? INS_cmpw : INS_cmpd);
}

static instruction ppcBranchInsForCondition(GenCondition cond)
{
    switch (cond.GetCode())
    {
        case GenCondition::EQ:
            return INS_beq;
        case GenCondition::NE:
            return INS_bne;
        case GenCondition::SLT:
        case GenCondition::ULT:
            return INS_blt;
        case GenCondition::SLE:
        case GenCondition::ULE:
            return INS_ble;
        case GenCondition::SGE:
        case GenCondition::UGE:
            return INS_bge;
        case GenCondition::SGT:
        case GenCondition::UGT:
            return INS_bgt;
        default:
            NO_WAY("unexpected PPC64LE branch condition");
            return INS_invalid;
    }
}

void CodeGen::genFnEpilog(BasicBlock* block)
{
    if (m_compiler->compLclFrameSize != 0)
    {
        genStackPointerAdjustment(m_compiler->compLclFrameSize, REG_TMP_0, nullptr, true);
    }

    GetEmitter()->emitIns(INS_blr);
}

void CodeGen::genCodeForTreeNode(GenTree* treeNode)
{
    switch (treeNode->OperGet())
    {
        case GT_CNS_INT:
        {
            regNumber targetReg = treeNode->GetRegNum();
            instGen_Set_Reg_To_Imm(emitActualTypeSize(treeNode), targetReg, treeNode->AsIntConCommon()->IconValue());
            genProduceReg(treeNode);
            break;
        }

        case GT_ADD:
        {
            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);
            GetEmitter()->emitIns_R_R_R(INS_add, emitActualTypeSize(treeNode), targetReg, op1->GetRegNum(),
                                        op2->GetRegNum());
            genProduceReg(treeNode);
            break;
        }

        case GT_SUB:
        {
            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);
            GetEmitter()->emitIns_R_R_R(INS_subf, emitActualTypeSize(treeNode), targetReg, op2->GetRegNum(),
                                        op1->GetRegNum());
            genProduceReg(treeNode);
            break;
        }

        case GT_MUL:
        {
            if (treeNode->gtOverflow())
            {
                NYI_POWERPC64("overflow-checking multiply");
            }

            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);
            GetEmitter()->emitIns_R_R_R(genGetInsForOper(treeNode), emitActualTypeSize(treeNode), targetReg,
                                        op1->GetRegNum(), op2->GetRegNum());
            genProduceReg(treeNode);
            break;
        }

        case GT_DIV:
        case GT_UDIV:
        case GT_MOD:
        case GT_UMOD:
            genCodeForDivMod(treeNode->AsOp());
            break;

        case GT_AND:
        case GT_OR:
        case GT_XOR:
        {
            GenTree*  op1       = treeNode->gtGetOp1();
            GenTree*  op2       = treeNode->gtGetOp2();
            regNumber targetReg = treeNode->GetRegNum();

            genConsumeRegs(op1);
            genConsumeRegs(op2);
            GetEmitter()->emitIns_R_R_R(genGetInsForOper(treeNode), emitActualTypeSize(treeNode), targetReg,
                                        op1->GetRegNum(), op2->GetRegNum());
            genProduceReg(treeNode);
            break;
        }

        case GT_LSH:
        case GT_RSH:
        case GT_RSZ:
            genCodeForShift(treeNode);
            break;

        case GT_NEG:
        case GT_NOT:
            genCodeForNegNot(treeNode->AsOp());
            break;

        case GT_EQ:
        case GT_NE:
        case GT_LT:
        case GT_LE:
        case GT_GE:
        case GT_GT:
            genCodeForCompare(treeNode->AsOp());
            break;

        case GT_CAST:
        {
            GenTreeCast* cast = treeNode->AsCast();
            if (varTypeIsIntegral(cast) && varTypeIsIntegral(cast->CastOp()))
            {
                genIntToIntCast(cast);
            }
            else if (varTypeIsFloating(cast) && varTypeIsFloating(cast->CastOp()))
            {
                genFloatToFloatCast(cast);
            }
            else if (varTypeIsIntegral(cast) && varTypeIsFloating(cast->CastOp()))
            {
                genFloatToIntCast(cast);
            }
            else
            {
                assert(varTypeIsFloating(cast) && varTypeIsIntegral(cast->CastOp()));
                genIntToFloatCast(cast);
            }
            break;
        }

        case GT_LCL_VAR:
            genCodeForLclVar(treeNode->AsLclVar());
            break;

        case GT_LCL_FLD:
            genCodeForLclFld(treeNode->AsLclFld());
            break;

        case GT_LCL_ADDR:
            genCodeForLclAddr(treeNode->AsLclFld());
            break;

        case GT_LEA:
            genLeaInstruction(treeNode->AsAddrMode());
            break;

        case GT_STORE_LCL_VAR:
            genCodeForStoreLclVar(treeNode->AsLclVar());
            break;

        case GT_STORE_LCL_FLD:
            genCodeForStoreLclFld(treeNode->AsLclFld());
            break;

        case GT_IND:
            genCodeForIndir(treeNode->AsIndir());
            break;

        case GT_NULLCHECK:
            genCodeForNullCheck(treeNode->AsIndir());
            break;

        case GT_STOREIND:
            genCodeForStoreInd(treeNode->AsStoreInd());
            break;

        case GT_JCMP:
            genCodeForJumpCompare(treeNode->AsOpCC());
            break;

        case GT_RETURN:
        case GT_RETFILT:
            genReturn(treeNode);
            break;

        case GT_MEMORYBARRIER:
        {
            BarrierKind barrierKind =
                treeNode->gtFlags & GTF_MEMORYBARRIER_LOAD
                    ? BARRIER_LOAD_ONLY
                    : (treeNode->gtFlags & GTF_MEMORYBARRIER_STORE ? BARRIER_STORE_ONLY : BARRIER_FULL);

            instGen_MemoryBarrier(barrierKind);
            break;
        }

        default:
            NYI_POWERPC64("genCodeForTreeNode");
            break;
    }
}

void CodeGen::genCodeForNegNot(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_NEG, GT_NOT));

    GenTree* operand = tree->gtGetOp1();
    regNumber operandReg = genConsumeReg(operand);
    regNumber targetReg  = tree->GetRegNum();

    assert(targetReg != REG_NA);
    assert(!varTypeIsFloating(tree));

    GetEmitter()->emitIns_R_R(genGetInsForOper(tree), emitActualTypeSize(tree), targetReg, operandReg);

    genProduceReg(tree);
}

void CodeGen::genCodeForShift(GenTree* tree)
{
    assert(tree->OperIsShift());
    assert(!varTypeIsFloating(tree));

    GenTree* operand = tree->gtGetOp1();
    GenTree* shiftBy = tree->gtGetOp2();

    genConsumeOperands(tree->AsOp());

    GetEmitter()->emitIns_R_R_R(genGetInsForOper(tree), emitActualTypeSize(tree), tree->GetRegNum(),
                                operand->GetRegNum(), shiftBy->GetRegNum());

    genProduceReg(tree);
}

void CodeGen::genCodeForDivMod(GenTreeOp* tree)
{
    assert(tree->OperIs(GT_DIV, GT_UDIV, GT_MOD, GT_UMOD));
    NYI_IF(varTypeIsFloating(tree), "floating point div/mod");

    if (tree->OperExceptions(m_compiler) != ExceptionSetFlags::None)
    {
        NYI_POWERPC64("exception-checking integer div/mod");
    }

    GenTree*  op1       = tree->gtGetOp1();
    GenTree*  op2       = tree->gtGetOp2();
    emitAttr  attr      = emitActualTypeSize(tree);
    regNumber targetReg = tree->GetRegNum();

    genConsumeRegs(op1);
    genConsumeRegs(op2);

    instruction divIns = genGetInsForOper(tree);
    if (tree->OperIs(GT_DIV, GT_UDIV))
    {
        GetEmitter()->emitIns_R_R_R(divIns, attr, targetReg, op1->GetRegNum(), op2->GetRegNum());
    }
    else
    {
        regNumber quotientReg = internalRegisters.GetSingle(tree);
        instruction mulIns    = (attr == EA_4BYTE) ? INS_mullw : INS_mulld;

        GetEmitter()->emitIns_R_R_R(divIns, attr, quotientReg, op1->GetRegNum(), op2->GetRegNum());
        GetEmitter()->emitIns_R_R_R(mulIns, attr, quotientReg, quotientReg, op2->GetRegNum());
        GetEmitter()->emitIns_R_R_R(INS_subf, attr, targetReg, quotientReg, op1->GetRegNum());
    }

    genProduceReg(tree);
}

void CodeGen::genCodeForCompare(GenTreeOp* tree)
{
    assert(tree->OperIsCmpCompare());
    assert(!tree->TypeIs(TYP_VOID));

    GenTree* op1 = tree->gtOp1;
    GenTree* op2 = tree->gtOp2;

    assert(!op1->isUsedFromMemory());
    assert(!op2->isUsedFromMemory());

    var_types op1Type = genActualType(op1->TypeGet());
    var_types op2Type = genActualType(op2->TypeGet());
    assert(genTypeSize(op1Type) == genTypeSize(op2Type));
    assert(varTypeIsIntegralOrI(op1Type));

    genConsumeOperands(tree);

    emitAttr     cmpSize   = emitActualTypeSize(op1Type);
    GenCondition cond      = GenCondition::FromIntegralRelop(tree);
    instruction  cmp       = ppcCompareInsForCondition(cond, cmpSize);
    regNumber    targetReg = tree->GetRegNum();
    assert(targetReg != REG_NA);

    GetEmitter()->emitIns_R_R(cmp, cmpSize, op1->GetRegNum(), op2->GetRegNum());

    BasicBlock* doneLabel = genCreateTempLabel();

    instGen_Set_Reg_To_Imm(emitActualTypeSize(tree), targetReg, 0);
    GetEmitter()->emitIns_J(ppcBranchInsForCondition(GenCondition::Reverse(cond)), doneLabel);
    instGen_Set_Reg_To_Imm(emitActualTypeSize(tree), targetReg, 1);

    genDefineTempLabel(doneLabel);
    genProduceReg(tree);
}

void CodeGen::genCodeForLclVar(GenTreeLclVar* tree)
{
    unsigned varNum = tree->GetLclNum();
    assert(varNum < m_compiler->lvaCount);

    LclVarDsc* varDsc = m_compiler->lvaGetDesc(varNum);
    assert((tree->gtFlags & GTF_VAR_DEF) == 0);

    if (!varDsc->lvIsRegCandidate() && !tree->IsMultiReg() && ((tree->gtFlags & GTF_SPILLED) == 0))
    {
        var_types targetType = varDsc->GetRegisterType(tree);
        assert(targetType != TYP_STRUCT);

        GetEmitter()->emitIns_R_S(ins_Load(targetType), emitTypeSize(targetType), tree->GetRegNum(), varNum, 0);
        genProduceReg(tree);
    }
}

void CodeGen::genCodeForLclFld(GenTreeLclFld* tree)
{
    assert(tree->OperIs(GT_LCL_FLD));
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_LCL_FLD: struct load local field not supported");

    var_types targetType = tree->TypeGet();
    regNumber targetReg  = tree->GetRegNum();
    assert(targetReg != REG_NA);

    GetEmitter()->emitIns_R_S(ins_Load(targetType), emitTypeSize(targetType), targetReg, tree->GetLclNum(),
                              tree->GetLclOffs());
    genProduceReg(tree);
}

void CodeGen::genCodeForLclAddr(GenTreeLclFld* lclAddrNode)
{
    assert(lclAddrNode->OperIs(GT_LCL_ADDR));

    var_types targetType = lclAddrNode->TypeGet();
    assert((targetType == TYP_BYREF) || (targetType == TYP_I_IMPL));

    bool fpBased = false;
    int  offset  = m_compiler->lvaFrameAddress(lclAddrNode->GetLclNum(), &fpBased) + lclAddrNode->GetLclOffs();

    regNumber baseReg   = fpBased ? REG_FPBASE : REG_SPBASE;
    regNumber targetReg = lclAddrNode->GetRegNum();
    assert(targetReg != REG_NA);

    if (emitter::isValidSimm16(offset))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, emitActualTypeSize(targetType), targetReg, baseReg, offset);
    }
    else
    {
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, targetReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, targetReg, baseReg, targetReg);
    }

    genProduceReg(lclAddrNode);
}

void CodeGen::genLeaInstruction(GenTreeAddrMode* lea)
{
    assert(lea->OperIs(GT_LEA));
    assert(lea->HasBase());
    assert(!lea->HasIndex());
    assert(lea->gtScale <= 1);

    genConsumeOperands(lea);

    emitAttr  size      = emitTypeSize(lea);
    int       offset    = lea->Offset();
    regNumber baseReg   = lea->Base()->GetRegNum();
    regNumber targetReg = lea->GetRegNum();

    if (emitter::isValidSimm16(offset))
    {
        if ((offset != 0) || (targetReg != baseReg))
        {
            GetEmitter()->emitIns_R_R_I(INS_addi, size, targetReg, baseReg, offset);
        }
    }
    else
    {
        regNumber tmpReg = internalRegisters.GetSingle(lea);
        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, offset);
        GetEmitter()->emitIns_R_R_R(INS_add, size, targetReg, baseReg, tmpReg);
    }

    genProduceReg(lea);
}

void CodeGen::genCodeForStoreLclFld(GenTreeLclFld* tree)
{
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_STORE_LCL_FLD: struct store local field not supported");

    GenTree* data = tree->gtOp1;
    genConsumeRegs(data);

    if (data->isContained())
    {
        NYI_POWERPC64("contained local field store data");
    }

    var_types targetType = tree->TypeGet();
    regNumber dataReg    = data->GetRegNum();
    assert(dataReg != REG_NA);

    GetEmitter()->emitIns_S_R(ins_StoreFromSrc(dataReg, targetType), emitTypeSize(targetType), dataReg,
                              tree->GetLclNum(), tree->GetLclOffs());

    genUpdateLife(tree);
    m_compiler->lvaGetDesc(tree->GetLclNum())->SetRegNum(REG_STK);
}

void CodeGen::genCodeForStoreLclVar(GenTreeLclVar* lclNode)
{
    GenTree* data = lclNode->gtOp1;

    if (data->gtSkipReloadOrCopy()->IsMultiRegNode() || lclNode->IsMultiReg())
    {
        NYI_POWERPC64("multi-reg local store");
    }

    LclVarDsc* varDsc     = m_compiler->lvaGetDesc(lclNode);
    regNumber  targetReg  = lclNode->GetRegNum();
    unsigned   varNum     = lclNode->GetLclNum();
    var_types  targetType = varDsc->GetRegisterType(lclNode);

    genConsumeRegs(data);

    if (data->isContained())
    {
        NYI_POWERPC64("contained local store data");
    }

    regNumber dataReg = data->GetRegNum();
    assert(dataReg != REG_NA);

    if (targetReg == REG_NA)
    {
        inst_set_SV_var(lclNode);

        GetEmitter()->emitIns_S_R(ins_StoreFromSrc(dataReg, targetType), emitActualTypeSize(targetType), dataReg,
                                  varNum, 0);

        genUpdateLife(lclNode);
        varDsc->SetRegNum(REG_STK);
    }
    else
    {
        GetEmitter()->emitIns_Mov(emitActualTypeSize(targetType), targetReg, dataReg, true);
        genProduceReg(lclNode);
    }
}

void CodeGen::genCodeForIndir(GenTreeIndir* tree)
{
    assert(tree->OperIs(GT_IND));
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_IND: struct load not supported");

    GenTree* addr = tree->Addr();
    assert(!addr->isContained());

    ssize_t offset = tree->Offset();
    if (!emitter::isValidSimm16(offset))
    {
        NYI_POWERPC64("GT_IND: large offset");
    }

    regNumber baseReg   = genConsumeReg(addr);
    var_types targetType = tree->TypeGet();
    regNumber targetReg  = tree->GetRegNum();

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    GetEmitter()->emitIns_R_AR(ins_Load(targetType), emitActualTypeSize(targetType), targetReg, baseReg,
                               static_cast<int>(offset));

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    genProduceReg(tree);
}

void CodeGen::genCodeForNullCheck(GenTreeIndir* tree)
{
    assert(tree->OperIs(GT_NULLCHECK));

    GenTree* addr = tree->Addr();
    assert(!addr->isContained());

    ssize_t offset = tree->Offset();
    if (!emitter::isValidSimm16(offset))
    {
        NYI_POWERPC64("GT_NULLCHECK: large offset");
    }

    regNumber baseReg = genConsumeReg(addr);
    GetEmitter()->emitIns_R_AR(ins_Load(tree->TypeGet()), emitActualTypeSize(tree), REG_R0, baseReg,
                               static_cast<int>(offset));
}

void CodeGen::genCodeForStoreInd(GenTreeStoreInd* tree)
{
    NYI_IF(tree->TypeIs(TYP_STRUCT), "GT_STOREIND: struct store not supported");
    NYI_IF(gcInfo.gcIsWriteBarrierCandidate(tree) != GCInfo::WBF_NoBarrier, "GT_STOREIND: write barrier not supported");

    GenTree* addr = tree->Addr();
    GenTree* data = tree->Data();
    assert(!addr->isContained());

    ssize_t offset = tree->Offset();
    if (!emitter::isValidSimm16(offset))
    {
        NYI_POWERPC64("GT_STOREIND: large offset");
    }

    regNumber baseReg = genConsumeReg(addr);

    genConsumeRegs(data);
    if (data->isContained())
    {
        NYI_POWERPC64("GT_STOREIND: contained data");
    }

    var_types type    = tree->TypeGet();
    regNumber dataReg = data->GetRegNum();
    assert(dataReg != REG_NA);

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }

    GetEmitter()->emitIns_AR_R(ins_StoreFromSrc(dataReg, type), emitActualTypeSize(type), dataReg, baseReg,
                               static_cast<int>(offset));

    if ((tree->gtFlags & GTF_IND_VOLATILE) != 0)
    {
        instGen_MemoryBarrier(BARRIER_FULL);
    }
}

void CodeGen::genCodeForJumpCompare(GenTreeOpCC* tree)
{
    assert(m_compiler->compCurBB->KindIs(BBJ_COND));

    assert(tree->OperIs(GT_JCMP));
    assert(!varTypeIsFloating(tree));
    assert(tree->TypeIs(TYP_VOID));
    assert(tree->GetRegNum() == REG_NA);

    GenTree* op1 = tree->gtGetOp1();
    GenTree* op2 = tree->gtGetOp2();
    assert(!op1->isUsedFromMemory());
    assert(!op2->isUsedFromMemory());

    var_types op1Type = genActualType(op1->TypeGet());
    var_types op2Type = genActualType(op2->TypeGet());
    assert(genTypeSize(op1Type) == genTypeSize(op2Type));
    assert(varTypeIsIntegralOrI(op1Type));

    genConsumeOperands(tree);

    emitAttr  cmpSize = emitActualTypeSize(op1Type);
    regNumber regOp1  = op1->GetRegNum();
    regNumber regOp2  = op2->GetRegNum();

    GenCondition cond = tree->gtCondition;
    instruction  cmp  = ppcCompareInsForCondition(cond, cmpSize);
    GetEmitter()->emitIns_R_R(cmp, cmpSize, regOp1, regOp2);

    GetEmitter()->emitIns_J(ppcBranchInsForCondition(cond), m_compiler->compCurBB->GetTrueTarget());

    BasicBlock* falseTarget = m_compiler->compCurBB->GetFalseTarget();
    if (!m_compiler->compCurBB->CanRemoveJumpToTarget(falseTarget, m_compiler))
    {
        inst_JMP(EJ_jmp, falseTarget);
    }
}

void CodeGen::genJumpToThrowHlpBlk_la(SpecialCodeKind codeKind,
                                      instruction     ins,
                                      regNumber       reg1,
                                      BasicBlock*     failBlk,
                                      regNumber       reg2)
{
    NYI_POWERPC64("genJumpToThrowHlpBlk_la");
}

bool CodeGen::genInstrWithConstant(
    instruction ins, emitAttr attr, regNumber reg1, regNumber reg2, ssize_t imm, regNumber tmpReg, bool inUnwindRegion)
{
    assert(tmpReg != reg2);

#ifdef DEBUG
    switch (ins)
    {
        case INS_addi:
        case INS_ld:
        case INS_lwz:
        case INS_lhz:
        case INS_lbz:
        case INS_std:
        case INS_stw:
        case INS_sth:
        case INS_stb:
            break;

        default:
            assert(!"Unexpected instruction in genInstrWithConstant");
            break;
    }
#endif

    if (emitter::isValidSimm16(imm))
    {
        GetEmitter()->emitIns_R_R_I(ins, attr, reg1, reg2, imm);
        return true;
    }

    assert(tmpReg != REG_NA);
    assert(!EA_IS_RELOC(EA_SIZE(attr)));

    instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, imm);
    regSet.verifyRegUsed(tmpReg);

    if (inUnwindRegion)
    {
        m_compiler->unwindPadding();
    }

    if (ins == INS_addi)
    {
        GetEmitter()->emitIns_R_R_R(INS_add, attr, reg1, reg2, tmpReg);
    }
    else
    {
#ifdef DEBUG
        bool isStore = false;
        switch (ins)
        {
            case INS_std:
            case INS_stw:
            case INS_sth:
            case INS_stb:
                isStore = true;
                break;
            default:
                break;
        }
        assert(!isStore || (tmpReg != reg1));
#endif
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, tmpReg, reg2, tmpReg);
        GetEmitter()->emitIns_R_R_I(ins, attr, reg1, tmpReg, 0);
    }

    return false;
}

void CodeGen::genStackPointerAdjustment(ssize_t spAdjustment, regNumber tmpReg, bool* pTmpRegIsZero, bool reportUnwindData)
{
    if (emitter::isValidSimm16(spAdjustment))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, EA_PTRSIZE, REG_SPBASE, REG_SPBASE, spAdjustment);
    }
    else
    {
        if (tmpReg == REG_NA)
        {
            NYI_POWERPC64("large stack adjustment without temporary register");
        }

        instGen_Set_Reg_To_Imm(EA_PTRSIZE, tmpReg, spAdjustment);
        GetEmitter()->emitIns_R_R_R(INS_add, EA_PTRSIZE, REG_SPBASE, REG_SPBASE, tmpReg);

        if (pTmpRegIsZero != nullptr)
        {
            *pTmpRegIsZero = false;
        }
    }

    if (reportUnwindData)
    {
        ssize_t spDeltaAbs = std::abs(spAdjustment);
        assert((spDeltaAbs % STACK_ALIGN) == 0);
        m_compiler->unwindAllocStack(static_cast<unsigned>(spDeltaAbs));
    }
}

void CodeGen::genSaveCalleeSavedRegistersHelp(regMaskTP regsToSaveMask, int lowestCalleeSavedOffset)
{
    NYI_POWERPC64("genSaveCalleeSavedRegistersHelp");
}

void CodeGen::genRestoreCalleeSavedRegistersHelp(regMaskTP regsToRestoreMask,
                                                 regNumber baseReg,
                                                 int       lowestCalleeSavedOffset,
                                                 bool      reportUnwindData)
{
    NYI_POWERPC64("genRestoreCalleeSavedRegistersHelp");
}

instruction CodeGen::genGetInsForOper(GenTree* treeNode)
{
    switch (treeNode->OperGet())
    {
        case GT_ADD:
            return INS_add;
        case GT_SUB:
            return INS_subf;
        case GT_MUL:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_mullw : INS_mulld;
        case GT_DIV:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divw : INS_divd;
        case GT_UDIV:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divwu : INS_divdu;
        case GT_MOD:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divw : INS_divd;
        case GT_UMOD:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_divwu : INS_divdu;
        case GT_LSH:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_slw : INS_sld;
        case GT_RSH:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_sraw : INS_srad;
        case GT_RSZ:
            return (emitActualTypeSize(treeNode) == EA_4BYTE) ? INS_srw : INS_srd;
        case GT_AND:
            return INS_and;
        case GT_OR:
            return INS_or;
        case GT_XOR:
            return INS_xor;
        case GT_NEG:
            return INS_neg;
        case GT_NOT:
            return INS_not;
        default:
            NYI_POWERPC64("genGetInsForOper");
            return INS_invalid;
    }
}

instruction CodeGen::genGetVolatileLdStIns(instruction currentIns, regNumber targetReg, GenTreeIndir* indir, bool* needsBarrier)
{
    assert(indir->IsVolatile());
    *needsBarrier = true;
    return currentIns;
}

bool CodeGen::genEmitOptimizedGCWriteBarrier(GCInfo::WriteBarrierForm writeBarrierForm, GenTree* addr, GenTree* data)
{
    return false;
}

int CodeGenInterface::genSPtoFPdelta() const
{
    return 0;
}

int CodeGenInterface::genTotalFrameSize() const
{
    return 0;
}

int CodeGenInterface::genCallerSPtoFPdelta() const
{
    return 0;
}

int CodeGenInterface::genCallerSPtoInitialSPdelta() const
{
    return 0;
}

void CodeGen::genCreateAndStoreGCInfo(unsigned codeSize, unsigned prologSize, unsigned epilogSize DEBUGARG(void* codePtr))
{
    IAllocator*    allowZeroAlloc = new (m_compiler, CMK_GC) CompIAllocator(m_compiler->getAllocatorGC());
    GcInfoEncoder* gcInfoEncoder  = new (m_compiler, CMK_GC)
        GcInfoEncoder(m_compiler->info.compCompHnd, m_compiler->info.compMethodInfo, allowZeroAlloc, NOMEM);
    assert(gcInfoEncoder != nullptr);

    gcInfo.gcInfoBlockHdrSave(gcInfoEncoder, codeSize, prologSize);

    unsigned callCnt = 0;
    gcInfo.gcMakeRegPtrTable(gcInfoEncoder, codeSize, prologSize, GCInfo::MAKE_REG_PTR_MODE_ASSIGN_SLOTS, &callCnt);
    gcInfoEncoder->FinalizeSlotIds();
    gcInfo.gcMakeRegPtrTable(gcInfoEncoder, codeSize, prologSize, GCInfo::MAKE_REG_PTR_MODE_DO_WORK, &callCnt);

    if (m_compiler->opts.IsReversePInvoke())
    {
        unsigned reversePInvokeFrameVarNumber = m_compiler->lvaReversePInvokeFrameVar;
        assert(reversePInvokeFrameVarNumber != BAD_VAR_NUM);
        const LclVarDsc* reversePInvokeFrameVar = m_compiler->lvaGetDesc(reversePInvokeFrameVarNumber);
        gcInfoEncoder->SetReversePInvokeFrameSlot(reversePInvokeFrameVar->GetStackOffset());
    }

    gcInfoEncoder->Build();

    m_compiler->compInfoBlkAddr = gcInfoEncoder->Emit();
    m_compiler->compInfoBlkSize = gcInfoEncoder->GetEncodedGCInfoSize();
}

void CodeGen::genEmitHelperCall(unsigned helper, int argSize, emitAttr retSize, regNumber callTargetReg)
{
    NYI_POWERPC64("genEmitHelperCall");
}

void CodeGen::genPushCalleeSavedRegisters(regNumber initReg, bool* pInitRegZeroed)
{
}

void CodeGen::genPopCalleeSavedRegisters(bool jmpEpilog)
{
}

void CodeGen::genOSRHandleTier0CalleeSavedRegistersAndFrame()
{
}

void CodeGen::genAllocLclFrame(unsigned frameSize, regNumber initReg, bool* pInitRegZeroed, regMaskTP maskArgRegsLiveIn)
{
    if (frameSize != 0)
    {
        genStackPointerAdjustment(-static_cast<ssize_t>(frameSize), initReg, pInitRegZeroed, true);
    }
}

void CodeGen::genZeroInitFrameUsingBlockInit(int untrLclHi, int untrLclLo, regNumber initReg, bool* pInitRegZeroed)
{
    if (untrLclHi > untrLclLo)
    {
        NYI_POWERPC64("genZeroInitFrameUsingBlockInit");
    }
}

void CodeGen::genSetGSSecurityCookie(regNumber initReg, bool* pInitRegZeroed)
{
}

void CodeGen::instGen_MemoryBarrier(BarrierKind barrierKind)
{
#ifdef DEBUG
    if (JitConfig.JitNoMemoryBarriers() == 1)
    {
        return;
    }
#endif // DEBUG

    GetEmitter()->emitIns(INS_sync);
}

#ifdef PROFILING_SUPPORTED
void CodeGen::genProfilingEnterCallback(regNumber initReg, bool* pInitRegZeroed)
{
    NYI_POWERPC64("genProfilingEnterCallback");
}

void CodeGen::genProfilingLeaveCallback(unsigned helper)
{
    NYI_POWERPC64("genProfilingLeaveCallback");
}
#endif // PROFILING_SUPPORTED

void CodeGen::genFuncletProlog(BasicBlock* block)
{
    NYI_POWERPC64("genFuncletProlog");
}

void CodeGen::genFuncletEpilog(BasicBlock* block)
{
    NYI_POWERPC64("genFuncletEpilog");
}

void CodeGen::genCaptureFuncletPrologEpilogInfo()
{
    NYI_POWERPC64("genCaptureFuncletPrologEpilogInfo");
}

void CodeGen::genEmitGSCookieCheck(bool tailCall)
{
    NYI_POWERPC64("genEmitGSCookieCheck");
}

void CodeGen::genJmpPlaceVarArgs()
{
    NYI_POWERPC64("genJmpPlaceVarArgs");
}

void CodeGen::genCallFinally(BasicBlock* block)
{
    NYI_POWERPC64("genCallFinally");
}

void CodeGen::genEHCatchRet(BasicBlock* block)
{
    NYI_POWERPC64("genEHCatchRet");
}

void CodeGen::genIntToIntCast(GenTreeCast* cast)
{
    genConsumeRegs(cast->gtGetOp1());

    GenIntCastDesc desc(cast);
    if (desc.CheckKind() != GenIntCastDesc::CHECK_NONE)
    {
        NYI_POWERPC64("overflow-checking integer cast");
    }

    emitter*        emit   = GetEmitter();
    const regNumber srcReg = cast->gtGetOp1()->GetRegNum();
    const regNumber dstReg = cast->GetRegNum();

    assert(genIsValidIntReg(srcReg));
    assert(genIsValidIntReg(dstReg));

    switch (desc.ExtendKind())
    {
        case GenIntCastDesc::ZERO_EXTEND_SMALL_INT:
        {
            unsigned clearBits = 64 - (desc.ExtendSrcSize() * BITS_PER_BYTE);
            emit->emitIns_R_R_I(INS_clrldi, EA_PTRSIZE, dstReg, srcReg, clearBits);
            break;
        }

        case GenIntCastDesc::SIGN_EXTEND_SMALL_INT:
        {
            instruction extend = (desc.ExtendSrcSize() == 1) ? INS_extsb : INS_extsh;
            emit->emitIns_R_R(extend, EA_PTRSIZE, dstReg, srcReg);
            break;
        }

        case GenIntCastDesc::ZERO_EXTEND_INT:
            emit->emitIns_R_R_I(INS_clrldi, EA_PTRSIZE, dstReg, srcReg, 32);
            break;

        case GenIntCastDesc::SIGN_EXTEND_INT:
            emit->emitIns_R_R(INS_extsw, EA_PTRSIZE, dstReg, srcReg);
            break;

        default:
            assert(desc.ExtendKind() == GenIntCastDesc::COPY);
            emit->emitIns_Mov(emitActualTypeSize(cast), dstReg, srcReg, true);
            break;
    }

    genProduceReg(cast);
}

void CodeGen::genFloatToFloatCast(GenTree* treeNode)
{
    NYI_POWERPC64("genFloatToFloatCast");
}

void CodeGen::genFloatToIntCast(GenTree* treeNode)
{
    NYI_POWERPC64("genFloatToIntCast");
}

void CodeGen::genIntToFloatCast(GenTree* treeNode)
{
    NYI_POWERPC64("genIntToFloatCast");
}

void CodeGen::genSimpleReturn(GenTree* treeNode)
{
    assert(treeNode->OperIs(GT_RETURN) || treeNode->OperIs(GT_RETFILT));

    GenTree* op1 = treeNode->gtGetOp1();
    if (op1 == nullptr)
    {
        return;
    }

    regNumber retReg = varTypeUsesFloatReg(treeNode) ? REG_FLOATRET : REG_INTRET;
    if (op1->GetRegNum() != retReg)
    {
        GetEmitter()->emitIns_Mov(emitActualTypeSize(treeNode), retReg, op1->GetRegNum(), true);
    }
}

void CodeGen::inst_JMP(emitJumpKind jmp, BasicBlock* tgtBlock)
{
    GetEmitter()->emitIns_J(emitter::emitJumpKindToIns(jmp), tgtBlock);
}

void CodeGen::instGen_Set_Reg_To_Imm(emitAttr  size,
                                     regNumber reg,
                                     ssize_t   imm,
                                     insFlags flags DEBUGARG(size_t targetHandle) DEBUGARG(GenTreeFlags gtFlags))
{
    auto signExtend16 = [](uint64_t value) -> ssize_t {
        ssize_t part = static_cast<ssize_t>(value & 0xFFFF);
        return (part >= 0x8000) ? (part - 0x10000) : part;
    };

    auto unsigned16 = [](uint64_t value) -> ssize_t {
        return static_cast<ssize_t>(value & 0xFFFF);
    };

    if (emitter::isValidSimm16(imm))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, size, reg, REG_R0, imm);
        return;
    }

    const uint64_t value = static_cast<uint64_t>(imm);

    if ((imm >= INT32_MIN) && (imm <= INT32_MAX))
    {
        ssize_t hi = signExtend16(value >> 16);
        ssize_t lo = unsigned16(value);

        GetEmitter()->emitIns_R_R_I(INS_addis, size, reg, REG_R0, hi);
        if (lo != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
        }
        return;
    }

    if ((imm >= 0) && (value <= UINT32_MAX))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, size, reg, REG_R0, 0);

        ssize_t hi = unsigned16(value >> 16);
        ssize_t lo = unsigned16(value);
        if (hi != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_oris, size, reg, reg, hi);
        }
        if (lo != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
        }
        return;
    }

    if ((imm >= -(1LL << 47)) && (imm < (1LL << 47)))
    {
        GetEmitter()->emitIns_R_R_I(INS_addi, size, reg, REG_R0, signExtend16(value >> 32));
        GetEmitter()->emitIns_R_R_I(INS_sldi, size, reg, reg, 32);

        ssize_t hi = unsigned16(value >> 16);
        ssize_t lo = unsigned16(value);
        if (hi != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_oris, size, reg, reg, hi);
        }
        if (lo != 0)
        {
            GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
        }
        return;
    }

    GetEmitter()->emitIns_R_R_I(INS_addis, size, reg, REG_R0, signExtend16(value >> 48));

    ssize_t next = unsigned16(value >> 32);
    if (next != 0)
    {
        GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, next);
    }

    GetEmitter()->emitIns_R_R_I(INS_sldi, size, reg, reg, 32);

    ssize_t hi = unsigned16(value >> 16);
    ssize_t lo = unsigned16(value);
    if (hi != 0)
    {
        GetEmitter()->emitIns_R_R_I(INS_oris, size, reg, reg, hi);
    }
    if (lo != 0)
    {
        GetEmitter()->emitIns_R_R_I(INS_ori, size, reg, reg, lo);
    }
}

// clang-format off
const GenConditionDesc GenConditionDesc::map[32]
{
    { },       // NONE
    { },       // 1
    { EJ_lt }, // SLT
    { EJ_le }, // SLE
    { EJ_ge }, // SGE
    { EJ_gt }, // SGT
    { },       // S
    { },       // NS

    { EJ_eq }, // EQ
    { EJ_ne }, // NE
    { EJ_lt }, // ULT
    { EJ_le }, // ULE
    { EJ_ge }, // UGE
    { EJ_gt }, // UGT
    { },       // C
    { },       // NC
};
// clang-format on

#endif // TARGET_POWERPC64
