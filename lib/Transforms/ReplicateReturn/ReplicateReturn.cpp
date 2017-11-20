//===- ReplicateReturn.cpp - Replicate return address and check on return---===//
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/Casting.h"
#include "llvm/IR/Intrinsics.h"

#include <vector>
#include <set>

using namespace llvm;

#define DEBUG_TYPE "replicateReturn"

namespace {
struct ReplicateReturn : public FunctionPass {
	static char ID; // Pass identification, replacement for typeid
	ReplicateReturn() : FunctionPass(ID) {}

	bool runOnFunction(Function &F) override {
		inst_iterator I = inst_begin(F);
		IRBuilder<> Builder (&*I);

		Module* M = F.getParent();

		// return address
		Value* arg0 = ConstantInt::get(Type::getInt32Ty(F.getContext()), 0);
		Function* getRetAddr   = Intrinsic::getDeclaration(
			M, Intrinsic::returnaddress);
		auto retAddr  = Builder.CreateCall(getRetAddr, arg0);

		auto retAddr1Loc = Builder.CreateAlloca(
			Type::getInt8PtrTy(F.getContext()), nullptr, "retAddrLoc1");
		Builder.CreateStore(retAddr, retAddr1Loc);

		auto retAddr2Loc = Builder.CreateAlloca(
			Type::getInt8PtrTy(F.getContext()), nullptr, "retAddrLoc2");
		Builder.CreateStore(retAddr, retAddr2Loc);

		// get all return instructions
		std::set<ReturnInst*> worklist;
		for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
			if(ReturnInst* ri = dyn_cast<ReturnInst>(&*I)) {
				worklist.insert(ri);
			}
		}

		Function* setRetAddr   = Intrinsic::getDeclaration(
			M, Intrinsic::setreturnaddress);

		for (auto ri : worklist) {
			BasicBlock* Check13Fail = BasicBlock::Create(
				F.getContext(), "repl.ret.check13.fail", &F);
			BasicBlock* Check23Fail  = BasicBlock::Create(
				F.getContext(), "repl.ret.check23.fail", &F);
			BasicBlock* TrapBlock = BasicBlock::Create(
				F.getContext(), "repl.ret.false.trap", &F);
			BasicBlock* RestoreBlock  = BasicBlock::Create(
				F.getContext(), "repl.ret.resture", &F);

			Builder.SetInsertPoint(ri);
			BasicBlock* curBB = Builder.GetInsertBlock();
			BasicBlock* ContBlock = curBB->splitBasicBlock(
				ri, "repl.ret.true.cont");

			Builder.SetInsertPoint(curBB->getTerminator());

			// get return address again
			auto retAddr3  = Builder.CreateCall(getRetAddr, arg0);

			// compare return addresses
			// addr1 and addr3
			auto retAddr1 = Builder.CreateLoad(retAddr1Loc);
			auto eq13  = Builder.CreateICmpEQ(retAddr1, retAddr3);
			ReplaceInstWithInst(
				curBB->getTerminator(),
				BranchInst::Create(ContBlock, Check13Fail, eq13));


			// if not equal
			// compare return addresses
			// addr2 and addr3
			Builder.SetInsertPoint(Check13Fail);
			auto retAddr2 = Builder.CreateLoad(retAddr2Loc);
			auto eq23  = Builder.CreateICmpEQ(retAddr2, retAddr3);

			// if equal just return (assumption: just addr1 was overwritten)
			Builder.CreateCondBr(eq23, ContBlock, Check23Fail);

			// if not equal (assumption: return address changed)
			// compare return addresses
			// add1 and addr2
			Builder.SetInsertPoint(Check23Fail);
			auto eq12  = Builder.CreateICmpEQ(retAddr1, retAddr2);

			// if equal
			// restore return address
			Builder.CreateCondBr(eq12, RestoreBlock, TrapBlock);

			Builder.SetInsertPoint(RestoreBlock);
			Builder.CreateCall(setRetAddr, retAddr3);
			Builder.CreateBr(ContBlock);

			// if not equal
			// terminate, unable to determine correct address
			Builder.SetInsertPoint(TrapBlock);
			Builder.CreateUnreachable();
		}

		return true;
	}
};
}

char ReplicateReturn::ID = 0;
static RegisterPass<ReplicateReturn> X("repl-return", "Replicate return address");
