; RUN: opt < %s -load LLVMReplicateReturn.so -repl-return -S | FileCheck %s

; CHECK: llvm.returnaddress
; CHECK: llvm.setreturnaddress
define void @test(i64* %p) {
  ret void
}