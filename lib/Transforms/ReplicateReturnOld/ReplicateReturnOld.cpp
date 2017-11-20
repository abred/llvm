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
		std::vector<Type*> params;
		params.push_back(Type::getInt8PtrTy(F.getContext()));
		FunctionType *printfType = FunctionType::get(Type::getInt32Ty(F.getContext()), params, true);
		FunctionType *abortType = FunctionType::get(Type::getVoidTy(F.getContext()), false);
		Value* printFh = M->getOrInsertFunction("printf",printfType);
		if(!printFh){
			errs() << "printf function not in symbol table\n";
			exit(1);
		}
		Value* aborth = M->getOrInsertFunction("abort",abortType);
		if(!printFh){
			errs() << "abort function not in symbol table\n";
			exit(1);
		}

		StringRef funcName = F.getName();
		Value* strFuncName = Builder.CreateGlobalStringPtr(funcName);

		Value* arg0 = ConstantInt::get(Type::getInt32Ty(F.getContext()), 0);
		Value* arg8 = ConstantInt::get(Type::getInt64Ty(F.getContext()), 8);

		// frame pointer
		Value* a = Builder.CreateAlloca(Type::getInt64PtrTy(F.getContext()));
		Function* getFramePointer = Intrinsic::getDeclaration(M, Intrinsic::frameaddress);
		Value* fa = Builder.CreateCall(getFramePointer, arg0);
		Value* fap = Builder.CreatePointerCast(fa, Type::getInt64PtrTy(F.getContext()));
		Builder.CreateStore(fap, a);

		// return address
		Function* getRetAddr   = Intrinsic::getDeclaration(M, Intrinsic::returnaddress);
		Value* a1 = Builder.CreateAlloca(Type::getInt64PtrTy(F.getContext()));
		Value* a2 = Builder.CreateAlloca(Type::getInt64PtrTy(F.getContext()));
		Value* ra1  = Builder.CreateCall(getRetAddr, arg0);
		Value* rap1 = Builder.CreatePointerCast(ra1, Type::getInt64PtrTy(F.getContext()));
		Value* s1 = Builder.CreateStore(rap1, a1);
		Value* s2 = Builder.CreateStore(rap1, a2);

		// get all return instructions
		std::set<ReturnInst*> worklist;
		for (inst_iterator I = inst_begin(F), E = inst_end(F); I != E; ++I) {
			if(ReturnInst* ri = dyn_cast<ReturnInst>(&*I)) {
				worklist.insert(ri);
			}
		}

		for (auto ri : worklist) {
			Builder.SetInsertPoint(ri);

			// strings
			StringRef stest = "p1: %p | p2: %p | v1: %p | v2: %p\n";
			Value* stestv = Builder.CreateGlobalStringPtr(stest);
			StringRef st = "Yes (same return address, function: %s)!\n";
			Value* strTrue = Builder.CreateGlobalStringPtr(st);
			StringRef sf = "Noo (different return address, function: %s)!\n";
			Value* strFalse= Builder.CreateGlobalStringPtr(sf);
			StringRef term = "Unable to determine return address. terminating...\n";
			Value* strTerm = Builder.CreateGlobalStringPtr(term);

			// check if return value is void
			bool retIsVoid;
			Value* retVal = ri->getReturnValue();
			if(retVal == nullptr) {
				retIsVoid = true;
			}
			else {
				retIsVoid = false;
				retVal = Constant::getNullValue(retVal->getType());
			}

			// get return address again
			Value* a3 = Builder.CreateAlloca(Type::getInt64PtrTy(F.getContext()));
			Value* ra3  = Builder.CreateCall(getRetAddr, arg0);
			Value* rap3 = Builder.CreatePointerCast(ra3, Type::getInt64PtrTy(F.getContext()));
			Value* s3 = Builder.CreateStore(rap3, a3);
			
			// compare return addresses
			// addr1 and addr3
			Value* t1 = Builder.CreateLoad(a1);
			Value* t2 = Builder.CreateLoad(a2);
			Value* t3 = Builder.CreateLoad(a3);
			Value* c1  = Builder.CreateICmpEQ(t1, t3);
			Builder.CreateCall(printFh, {stestv, a1, a3, t1, t3});

			// if equal just return
			BasicBlock* blockTrue1  = BasicBlock::Create(F.getContext(), "", &F);
			BasicBlock* blockFalse1 = BasicBlock::Create(F.getContext(), "", &F);
			BasicBlock::iterator ii(ri);
			ReplaceInstWithInst(ri->getParent()->getInstList(), ii,
					    BranchInst::Create(blockTrue1,blockFalse1,c1));

			Builder.SetInsertPoint(blockTrue1);
			Builder.CreateCall(printFh, {strTrue, strFuncName});
			retIsVoid ? Builder.CreateRetVoid() : Builder.CreateRet(retVal);

			// if not equal
			// compare return addresses
			// addr2 and addr3
			Builder.SetInsertPoint(blockFalse1);
			Builder.CreateCall(printFh, {strFalse, strFuncName});

			Value* c2  = Builder.CreateICmpEQ(t2, t3);
			Builder.CreateCall(printFh, {stestv, a2, a3, t2, t3});

			// if equal just return (assumption: just addr1 was overwritten)
			BasicBlock* blockTrue2  = BasicBlock::Create(F.getContext(), "", &F);
			BasicBlock* blockFalse2 = BasicBlock::Create(F.getContext(), "", &F);
			Builder.CreateCondBr(c2, blockTrue2, blockFalse2);
//			BasicBlock::iterator ii2(ri);
//			ReplaceInstWithInst(ri->getParent()->getInstList(), ii2,
//					    BranchInst::Create(blockTrue2,blockFalse2,c2));

			Builder.SetInsertPoint(blockTrue2);
			Builder.CreateCall(printFh, {strTrue, strFuncName});
			retIsVoid ? Builder.CreateRetVoid() : Builder.CreateRet(retVal);

			// if not equal (assumption: return address changed)
			// compare return addresses
			// add1 and addr2
			Builder.SetInsertPoint(blockFalse2);
			Builder.CreateCall(printFh, {strFalse, strFuncName});

			Value* c3  = Builder.CreateICmpEQ(t1, t2);
			Builder.CreateCall(printFh, {stestv, a1, a2, t1, t2});

			// if equal
			// restore return address
			BasicBlock* blockTrue3  = BasicBlock::Create(F.getContext(), "", &F);
			BasicBlock* blockFalse3 = BasicBlock::Create(F.getContext(), "", &F);
			Builder.CreateCondBr(c3, blockTrue3, blockFalse3);
//			BasicBlock::iterator ii3(ri);
//			ReplaceInstWithInst(ri->getParent()->getInstList(), ii3,
//					    BranchInst::Create(blockTrue3,blockFalse3,c3));

			Builder.SetInsertPoint(blockTrue3);
			Builder.CreateCall(printFh, {strTrue, strFuncName});
			Value* tfp = Builder.CreateLoad(a);
			tfp = Builder.CreateGEP(tfp, Builder.getInt64(1));
			Value* temp = Builder.CreatePtrToInt(t1, (Type::getInt64Ty(F.getContext())));
			Builder.CreateStore(temp, tfp);
			retIsVoid ? Builder.CreateRetVoid() : Builder.CreateRet(retVal);

			// if not equal
			// terminate, unable to determine correct address
			Builder.SetInsertPoint(blockFalse3);
			Builder.CreateCall(printFh, {strFalse, strFuncName});
			Builder.CreateCall(printFh, strTerm);
			Builder.CreateCall(aborth);
			retIsVoid ? Builder.CreateRetVoid() : Builder.CreateRet(retVal);
		}

		return true;
	}
};
}

char ReplicateReturn::ID = 0;
static RegisterPass<ReplicateReturn> X("repl-return", "Replicate return address");
