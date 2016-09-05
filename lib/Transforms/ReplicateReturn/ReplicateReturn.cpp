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

#include <set>

using namespace llvm;

#define DEBUG_TYPE "replicateReturn"

namespace {
struct ReplicateReturn : public FunctionPass {
static char ID;
ReplicateReturn() : FunctionPass(ID) {}

bool runOnFunction(Function &F) override {
	inst_iterator I = inst_begin(F);
	IRBuilder<> Builder (&*I);
	Module* M = F.getParent();

	auto trapIntrin = Intrinsic::getDeclaration(M, Intrinsic::trap);
	auto getRA = Intrinsic::getDeclaration(M, Intrinsic::returnaddress);
	auto setRA = Intrinsic::getDeclaration(M, Intrinsic::setreturnaddress);

	auto retAddr1 = Builder.CreateAlloca(Builder.getInt8PtrTy(),
					     nullptr, "retAddr1");
	auto retAddr2 = Builder.CreateAlloca(Builder.getInt8PtrTy(),
					     nullptr, "retAddr2");
	auto retAddr = Builder.CreateCall(getRA, Builder.getInt32(0));
	Builder.CreateStore(retAddr, retAddr1);
	Builder.CreateStore(retAddr, retAddr2);

	// get all return instructions
	std::set<ReturnInst*> worklist;
	for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
		if(ReturnInst* ri = dyn_cast<ReturnInst>(&*I)) {
			worklist.insert(ri);
		}
	}

	for (auto ri : worklist) {
		Builder.SetInsertPoint(ri);
		Value* retVal = ri->getReturnValue();

		auto ContBlock   = BasicBlock::Create(F.getContext(),
						      "repl.ret.true.cont", &F);
		auto Check13Fail = BasicBlock::Create(F.getContext(),
						      "repl.ret.check13.fail",
						      &F);
		auto Check23Fail = BasicBlock::Create(F.getContext(),
						      "repl.ret.check23.fail",
						      &F);
		auto RestoreRetAddr  = BasicBlock::Create(F.getContext(),
							  "repl.ret.restore",
							  &F);
		auto Trap = BasicBlock::Create(F.getContext(),
					       "repl.ret.false.trap", &F);

		auto r3  = Builder.CreateCall(getRA, Builder.getInt32(0),
					      "retAddr3");
		auto r1 = Builder.CreateLoad(retAddr1, "retAddr1");
		auto eq13  = Builder.CreateICmpEQ(r1, r3, "comp13");
		BasicBlock::iterator ii(ri);
		ReplaceInstWithInst(ri->getParent()->getInstList(), ii,
				    BranchInst::Create(ContBlock,
						       Check13Fail,
						       eq13));

		Builder.SetInsertPoint(Trap);
		Builder.CreateCall(trapIntrin, {});
		Builder.CreateUnreachable();

		Builder.SetInsertPoint(Check13Fail);
		auto r2 = Builder.CreateLoad(retAddr2, "retAddr2");
		auto eq23  = Builder.CreateICmpEQ(r2, r3, "comp23");
		Builder.CreateCondBr(eq23, ContBlock, Check23Fail);

		Builder.SetInsertPoint(Check23Fail);
		auto eq12  = Builder.CreateICmpEQ(r1, r2, "comp12");
		Builder.CreateCondBr(eq12, RestoreRetAddr, Trap);

		Builder.SetInsertPoint(RestoreRetAddr);
		Builder.CreateCall(setRA, {r1});
		Builder.CreateBr(ContBlock);

		Builder.SetInsertPoint(ContBlock);
		retVal == nullptr ?
			Builder.CreateRetVoid() : Builder.CreateRet(retVal);
	}

	return true;
}
};
}

char ReplicateReturn::ID = 0;
static RegisterPass<ReplicateReturn> X("repl-return", "Replicate return address");
