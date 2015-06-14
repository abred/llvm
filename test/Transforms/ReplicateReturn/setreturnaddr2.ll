; RUN: opt < %s -load LLVMReplicateReturn.so -repl-return -S | FileCheck %s
; RUN: opt < %s -load LLVMReplicateReturn.so -repl-return -S > %t1.ll
; RUN: clang -o %t2 %t1.ll
; RUN: %t2
; RUN: clang -o %t3 %s
; RUN: not %t3

; CHECK: llvm.returnaddress
; CHECK: llvm.setreturnaddress
define void @a() {
entry:
  call void @exit(i32 1)
  unreachable
}

declare void @exit(i32)

; CHECK: llvm.returnaddress
; CHECK: llvm.setreturnaddress
; CHECK: llvm.setreturnaddress
define void @b(){
entry:
  call void @llvm.setreturnaddress(i8* bitcast (void ()* @a to i8*))
  ret void
}

declare void @llvm.setreturnaddress(i8*)

; CHECK: llvm.returnaddress
; CHECK: llvm.setreturnaddress
define i32 @main(){
entry:
  call void @b()
  ret i32 0
}