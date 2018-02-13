#include <string>
#include "llvm/MC/MCContext.h"
#include <iostream>
//===-- X86FixupLEAs.cpp - use or replace LEA instructions -----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the pass that finds instructions that can be
// re-written as LEA instructions in order to reduce pipeline delays.
//
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrInfo.h"
#include "X86Subtarget.h"
#include "X86InstrBuilder.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/LiveVariables.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetInstrInfo.h"
using namespace llvm;

#define DEBUG_TYPE "protect-spill"

namespace {
class ProtectSpillSupportPass : public MachineFunctionPass {
  static char ID;

  const char *getPassName() const override { return "X86 Support for protection of register spills"; }

  typedef struct {
    MachineInstr *MI;
    unsigned NativeOpcode;
    bool isFrameSetup;
    bool isEFLAGSlive;
    bool isRAXlive;  
  } CJEItem;

public:
  ProtectSpillSupportPass() : MachineFunctionPass(ID) {}

  bool runOnMachineFunction(MachineFunction &Func) override;

  bool isRAXLiveAtMI(MachineInstr *MI) const;
  bool isRCXLiveAtMI(MachineInstr *MI) const;
  bool isRDXLiveAtMI(MachineInstr *MI) const;
  bool isRBXLiveAtMI(MachineInstr *MI) const;
  bool isRBPLiveAtMI(MachineInstr *MI) const;
  bool isRSILiveAtMI(MachineInstr *MI) const;
  bool isRDILiveAtMI(MachineInstr *MI) const;

  MachineBasicBlock::iterator insertDoubleXchange(MachineBasicBlock::iterator I, MachineBasicBlock::iterator MI);

  void transformCJE(MachineBasicBlock::iterator MI,
                    unsigned NativeOpc, bool isFrameSetup,
                    bool isEFLAGSlive, bool isRAXlive);
  bool findReg(MachineBasicBlock::iterator MI);
};
char ProtectSpillSupportPass::ID = 0;
}

bool ProtectSpillSupportPass::isRCXLiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RCX, MI, true) ||
      TII->isRegLiveAtMI(X86::ECX, MI, true) ||
      TII->isRegLiveAtMI(X86::CX, MI, true) ||
      TII->isRegLiveAtMI(X86::CH, MI, true))
    // The 'AL' subregister does not matter for the purposes of the
    // 'ProtectSpillSupportPass' since the instructions for saving and
    // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;

  return false;
}

bool ProtectSpillSupportPass::isRDXLiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RDX, MI, true) ||
      TII->isRegLiveAtMI(X86::EDX, MI, true) ||
      TII->isRegLiveAtMI(X86::DX, MI, true) ||
      TII->isRegLiveAtMI(X86::DH, MI, true))
    // The 'AL' subregister does not matter for the purposes of the
    // 'ProtectSpillSupportPass' since the instructions for saving and
    // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;

  return false;
}

bool ProtectSpillSupportPass::isRBXLiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RBX, MI, true) ||
      TII->isRegLiveAtMI(X86::EBX, MI, true) ||
      TII->isRegLiveAtMI(X86::BX, MI, true) ||
      TII->isRegLiveAtMI(X86::BH, MI, true))
    // The 'AL' subregister does not matter for the purposes of the
    // 'ProtectSpillSupportPass' since the instructions for saving and
    // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;

  return false;
}
bool ProtectSpillSupportPass::isRBPLiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RBP, MI, true) ||
      TII->isRegLiveAtMI(X86::EBP, MI, true) ||
      TII->isRegLiveAtMI(X86::BP, MI, true))
      // The 'AL' subregister does not matter for the purposes of the
      // 'ProtectSpillSupportPass' since the instructions for saving and
      // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;
    
  return false;
}
bool ProtectSpillSupportPass::isRSILiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RSI, MI, true) ||
      TII->isRegLiveAtMI(X86::ESI, MI, true) ||
      TII->isRegLiveAtMI(X86::SI, MI, true))
    // The 'AL' subregister does not matter for the purposes of the
    // 'ProtectSpillSupportPass' since the instructions for saving and
    // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;

  return false;
}
bool ProtectSpillSupportPass::isRDILiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RDI, MI, true) ||
      TII->isRegLiveAtMI(X86::EDI, MI, true) ||
      TII->isRegLiveAtMI(X86::DI, MI, true))
    // The 'AL' subregister does not matter for the purposes of the
    // 'ProtectSpillSupportPass' since the instructions for saving and
    // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;

  return false;
}
bool ProtectSpillSupportPass::isRAXLiveAtMI(MachineInstr *MI) const{
  const MachineFunction *MF = MI->getParent()->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  if (TII->isRegLiveAtMI(X86::RAX, MI, true) ||
      TII->isRegLiveAtMI(X86::EAX, MI, true) ||
      TII->isRegLiveAtMI(X86::AX, MI, true) ||
      TII->isRegLiveAtMI(X86::AH, MI, true))
    // The 'AL' subregister does not matter for the purposes of the
    // 'ProtectSpillSupportPass' since the instructions for saving and
    // restoring 'EFLAGS'(i.e. 'LAHF'/'SAHF') only use 'AH'.
    return true;

  return false;
}

bool ProtectSpillSupportPass::findReg(MachineBasicBlock::iterator MI) {
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();

  const TargetInstrInfo *TII = MF->getSubtarget().getInstrInfo();
  const X86Subtarget &STI = MF->getTarget().getSubtarget<X86Subtarget>(*(MF->getFunction()));

  unsigned REG = 0;
  if (!isRCXLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RCX : X86::ECX;
  }
  else if (!isRDXLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RDX : X86::EDX;
  }
  else if (!isRBXLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RBX : X86::EBX;
  }
  else if (!isRSILiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RSI : X86::ESI;
  }
  else if (!isRDILiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RDI : X86::EDI;
  }
  else if (!isRBPLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RBP : X86::EBP;
  }
  else {
    std::cout << "oooooooooooyerteghsdfgdooooooooo" << std::endl;
    return false;
  }
  return true;
}

MachineBasicBlock::iterator ProtectSpillSupportPass::insertDoubleXchange(MachineBasicBlock::iterator I, MachineBasicBlock::iterator MI) {
  MachineBasicBlock *MBB = I->getParent();
  MachineFunction *MF = MBB->getParent();

  const TargetInstrInfo *TII = MF->getSubtarget().getInstrInfo();
  const X86Subtarget &STI = MF->getTarget().getSubtarget<X86Subtarget>(*(MF->getFunction()));

  unsigned REG = 0;
  if (!isRCXLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RCX : X86::ECX;
  }
  else if (!isRDXLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RDX : X86::EDX;
  }
  else if (!isRBXLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RBX : X86::EBX;
  }
  else if (!isRSILiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RSI : X86::ESI;
  }
  else if (!isRDILiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RDI : X86::EDI;
  }
  else if (!isRBPLiveAtMI(MI)) {
    REG = STI.is64Bit() ? X86::RBP : X86::EBP;
  }
  else {
    std::cout << "asdfdddddddddddddddddddddddddddddddddddddddddddddddddddddd" << std::endl;
    return nullptr;
  }

  // unsigned REG = STI.is64Bit() ? X86::RBX : X86::EBX;
  unsigned XchgOpc = STI.is64Bit() ? X86::XCHG64ar : X86::XCHG32ar;

  const DebugLoc &DL = I->getDebugLoc();

  // Save 'RAX' before 'LAHF'/'SAHF' instruction:
  MachineBasicBlock::iterator result =
    BuildMI(*MBB, I, DL, TII->get(XchgOpc)).addReg(REG);
  // Restore 'RAX' and save 'EFLAGS' in 'RBX' register after
  // 'LAHF'/'SAHF' instruction:
  BuildMI(*MBB, std::next(I), DL, TII->get(XchgOpc)).addReg(REG);
  return result;
}

static bool isCJEOpcode(unsigned Opcode,
                        unsigned &NativeOpcode, bool &isFrameSetup) {
  bool result = false;
  NativeOpcode = ~0U;
  isFrameSetup = false;

  switch (Opcode) {
  case X86::FS_CJE64rm:
    isFrameSetup = true;
  case X86::CJE64rm:
    NativeOpcode = X86::CMP64rm;
    result = true;
    break;

  case X86::FS_CJE32rm:
    isFrameSetup = true;
  case X86::CJE32rm:
    NativeOpcode = X86::CMP32rm;
    result = true;
    break;

  case X86::FS_CJE16rm:
    isFrameSetup = true;
  case X86::CJE16rm:
    NativeOpcode = X86::CMP16rm;
    result = true;
    break;

  case X86::FS_CJE8rm:
    isFrameSetup = true;
  case X86::CJE8rm:
    NativeOpcode = X86::CMP8rm;
    result = true;
    break;

  case X86::CJEf64rm:
    NativeOpcode = X86::FCOM64m;
    break;
  case X86::CJEf32rm:
    NativeOpcode = X86::FCOM32m;
    result = true;
    break;

  default:
    break;
  }

  return result;
}

void ProtectSpillSupportPass::transformCJE(MachineBasicBlock::iterator MI,
                         unsigned NativeOpc, bool isFrameSetup,
                         bool isEFLAGSlive, bool isRAXlive) {
  DebugLoc DL = MI->getDebugLoc();
  DL.metaData = "TCJE";
  MachineBasicBlock *MBB = MI->getParent();
  MachineFunction *MF = MBB->getParent();
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(MF->getSubtarget().getInstrInfo());

  MachineBasicBlock::iterator JumpI = MI;
  if (isEFLAGSlive)
  {
    bool needProt = true;
    // bool usePrev = false;
    bool usePrevPrev = false;
    MachineBasicBlock::iterator prevMI = nullptr;
    MachineBasicBlock::iterator prevprevMI = nullptr;
    std::cout << std::string(MF->getName()) << "mi"
              << TII->getName(MI->getOpcode()) << " "
              << TII->isRegLiveAtMI(X86::EFLAGS, MI) << std::endl;
    if (MBB->begin() != MI) {
      prevMI = std::prev(MI);
      std::cout << std::string(MF->getName()) << "prevmi"
                << TII->getName(prevMI->getOpcode()) << " "
                << TII->isRegLiveAtMI(X86::EFLAGS, prevMI) << std::endl;
      // if (!TII->isRegLiveAtMI(X86::EFLAGS, prevMI)) {
      //   usePrev = true;
      // }
      // else
      if (MBB->begin() != prevMI) {
        prevprevMI = std::prev(prevMI);
        std::cout << std::string(MF->getName()) << "prevprevmi"
                  << TII->getName(prevprevMI->getOpcode()) << " "
                  << TII->isRegLiveAtMI(X86::EFLAGS, prevprevMI) << std::endl;
        if (!TII->isRegLiveAtMI(X86::EFLAGS, prevprevMI)) {
          usePrevPrev = true;
        }
      }

      // if (usePrev) {
      //   MI = MI->removeFromParent();
      //   MI = MI->removeFromParent();
      //   MI = MBB->insert(prevMI, MI);
      //   needProt = false;
      // }
      // else
      if (usePrevPrev) {
        MI = MI->removeFromParent();
        prevMI = prevMI->removeFromParent();
        prevMI = MBB->insert(prevprevMI, prevMI);
        MI = MBB->insert(prevprevMI, MI);
        needProt = false;
      }
      else {
        bool foundReg = findReg(MI);
        if (foundReg || !isRAXlive) {
          MachineBasicBlock::iterator LAHF =
            BuildMI(*MBB, MI, DL, TII->get(X86::LAHF));
          MachineBasicBlock::iterator SAHF =
            BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SAHF));

          JumpI = SAHF;
          if (isRAXlive) {
            insertDoubleXchange(LAHF, MI);
            JumpI = insertDoubleXchange(SAHF, MI);
          }
          needProt = false;
        }
      }
    }
  // }

    // if (TII->isRegLiveAtMI(X86::EFLAGS, prevprevMI)){
    //   bool foundReg = findReg(MI);
    //   if (foundReg || !isRAXlive) {
    //     MachineBasicBlock::iterator LAHF =
    //       BuildMI(*MBB, MI, DL, TII->get(X86::LAHF));
    //     MachineBasicBlock::iterator SAHF =
    //       BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SAHF));

    //     JumpI = SAHF;
    //     if (isRAXlive) {
    //       insertDoubleXchange(LAHF, MI);
    //       JumpI = insertDoubleXchange(SAHF, MI);
    //     }
    //   }
    //   else {
    //   }
    // }
    // else {
    //   MI = MI->removeFromParent();
    //   MBB->insert(prevMI, MI);
    // }

    if (needProt) {
      const X86RegisterInfo *TRI =
        static_cast<const X86RegisterInfo*>(MF->getSubtarget().getRegisterInfo());
      unsigned reg = TRI->getStackRegister();
      MachineBasicBlock::iterator LAHF =
        BuildMI(*MBB, std::prev(MI), DL, TII->get(X86::PUSHF32));
      BuildMI(*MBB, std::prev(MI), DL, TII->get(X86::ADD32ri8), reg)
        .addReg(reg)
        .addImm(4);
      MachineBasicBlock::iterator SAHF =
        BuildMI(*MBB, std::next(MI), DL, TII->get(X86::POPF32));

      BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SUB32ri8), reg)
        .addReg(reg)
        .addImm(4);
    }
    // const X86RegisterInfo *TRI =
    //   static_cast<const X86RegisterInfo*>(MF->getSubtarget().getRegisterInfo());
    // unsigned reg = TRI->getStackRegister();
    // MachineBasicBlock::iterator LAHF =
    //   BuildMI(*MBB, std::prev(MI), DL, TII->get(X86::PUSHF32));
    // BuildMI(*MBB, std::prev(MI), DL, TII->get(X86::ADD32ri8), reg)
    //   .addReg(reg)
    //   .addImm(4);
    // MachineBasicBlock::iterator SAHF =
    //   BuildMI(*MBB, std::next(MI), DL, TII->get(X86::POPF32));

    // BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SUB32ri8), reg)
    //   .addReg(reg)
    //   .addImm(4);
    // MachineBasicBlock::iterator LAHF =
    //   BuildMI(*MBB, MI, DL, TII->get(X86::LAHF));
    // MachineBasicBlock::iterator SAHF =
    //   BuildMI(*MBB, std::next(MI), DL, TII->get(X86::SAHF));

    // JumpI = SAHF;
    // if (isRAXlive) {
    //   insertDoubleXchange(LAHF, MI);
    //   JumpI = insertDoubleXchange(SAHF, MI);
    // }
  }

  // BuildMI(*MBB, MI, DL, TII->get(X86::NOOP));
  unsigned StartIndex = 0;
  int iseax = 0;
  // std::cout << "operands" << std::endl;

  // for (unsigned i = 0; i < MI->getNumOperands(); i++) {
  //   std::cout << i << " " << MI->getOperand(i).getType() << std::endl;
  //   if (MI->getOperand(i).isImm()) {
  //     std::cout << "imm" << MI->getOperand(i).getImm() << std::endl;
  //   }
  //   if (MI->getOperand(i).isFI()) {
  //     std::cout << "fi" << MI->getOperand(i).getIndex() << std::endl;
  //   }
  //   if (MI->getOperand(i).isReg()) {
  //     std::cout << "reg" << MI->getOperand(i).getReg() << " " << MF->getContext().getRegisterInfo()->getName(MI->getOperand(i).getReg()) << std::endl;
  //   }
  // }
  MachineInstr *CmpI = BuildMI(*MBB, MI, DL, TII->get(NativeOpc));
  // Transfer all operands of the CJE instruction: (Note that operands
  // were added to CJE using the 'addFrameReference' function. Therefore,
  // the exact number and types of operands are not known.)
  // unsigned StartIndex = isFrameSetup ? 0 : 1;

  // assert(MI->getOperand(2).isFI() && MI->getOperand(1).isReg());
  // std::cout << MI->getNumOperands() << std::endl;
  for (unsigned i = StartIndex; i < MI->getNumOperands(); i++) {
    // std::cout << MI->getOperand(i) << std::endl;
    CmpI->addOperand(MI->getOperand(i));
  }
  // MachineBasicBlock* tmpBlock1 = MF->CreateMachineBasicBlock();
  // MachineBasicBlock* tmpBlock2 = MF->CreateMachineBasicBlock();
  // MachineInstr *Jump1MI = BuildMI(*MBB, JumpI, DL, TII->get(X86::JE_1))
  //   .addMBB(tmpBlock1);
  // tmpBlock1->addPredecessor(MBB);
  // tmpBlock1->splice(tmpBlock1->begin(), MBB, MI, MBB->end());

  // tmpBlock2->splice(tmpBlock2->begin(), tmpBlock1, MI);
  // tmpBlock2->addPredecessor(MBB);
  // MachineInstr *JumpMI = BuildMI(*tmpBlock2, JumpI, DL, TII->get(X86::JMP_1))
  //   .addMBB(MF->getExitBlock());

  // BuildMI(*MBB, JumpI, DL, TII->get(X86::NOOP));
  MachineInstr *JumpMI = BuildMI(*MBB, JumpI, DL, TII->get(X86::JNE_1))
                          .addMBB(MF->getExitBlock());
  // // The EFLAGS are not needed in subsequent instructions.
  // // Hence, kill EFLAGS:
    // if (JumpMI->getOperand(1).isReg()) {
    //   std::cout << "reg" << JumpMI->getOperand(1).getReg() << " "
    //             << MF->getContext().getRegisterInfo()->getName(JumpMI->getOperand(1).getReg())
    //             << std::endl;
    // }
  JumpMI->getOperand(1).setIsKill(true);
  // // Set the 'ExitJump' flag so that the jump is not mistaken as a
  // // "conventional" terminator: (Not mistaking it for a terminator
  // // is important for the isnertion of function epilogs.)
  JumpMI->setFlag(MachineInstr::ExitJump);
  // // Add the basic block 'MBB' to the predecessors of the current
  // // machine function's 'ExitBlock':
  // // MF->getExitBlock()->addPredecessor(tmpBlock2);
  MF->getExitBlock()->addPredecessor(MBB);

  MI->eraseFromParent();
  MBB->updateTerminator();

}
bool ProtectSpillSupportPass::runOnMachineFunction(MachineFunction &Func) {
  const X86InstrInfo *TII =
    static_cast<const X86InstrInfo*>(Func.getSubtarget().getInstrInfo());

  bool modified = false;

  auto nm = Func.getName();
  // std::cout << std::string(nm);
  if (nm.find("boot") != StringRef::npos ||
      nm.find("libc") != StringRef::npos ||
      nm.find("exit") != StringRef::npos) {
    // std::cout << "  nope --------------";
    return modified;
  }
  // std::cout << std::endl;
  SmallVector<CJEItem, 8> worklist;

  for (auto MBBI = Func.begin(), MBBE = Func.end(); MBBI != MBBE; ++MBBI) {
    for (auto MI = MBBI->begin(), ME = MBBI->end(); MI != ME; ++MI) {
      CJEItem item;
      if (isCJEOpcode(MI->getOpcode(), item.NativeOpcode, item.isFrameSetup)) {
          item.MI = MI;
          item.isEFLAGSlive = TII->isRegLiveAtMI(X86::EFLAGS, MI);
          item.isRAXlive = isRAXLiveAtMI(MI);
          // We put 'CJE'instructions on a work list. Since transforming 'CJE'
          // instructions may introduce additional uses and definitions of 'RAX'
          // (when 'EFLAGS' needs to be saved and restored). There is a change
          // that these additional definitions and uses may confuse our
          // procedure for determining live-ness. Therefore, we determine
          // live-ness of 'EFFLAGS' and 'RAX' now, and also put this 
          // information on the work list.
          worklist.push_back(item);
      }
    }
  }

  modified = !worklist.empty();

  for (CJEItem item : worklist) {
    transformCJE(item.MI, item.NativeOpcode, item.isFrameSetup,
                 item.isEFLAGSlive, item.isRAXlive);
  }
  // while (!worklist.empty()) {
  //   CJEItem item = worklist.pop_back_val();
  //   transformCJE(item.MI, item.NativeOpcode, item.isFrameSetup,
  //                item.isEFLAGSlive, item.isRAXlive);
  // }

  return modified;
}

FunctionPass *llvm::createX86ProtectSpillSupport() { return new ProtectSpillSupportPass; }
