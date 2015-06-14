Resilient compiler
==================

The aim is to incorporate software fault tolerance techniques into llvm and
clang to build a resilient compiler.

Check *README.md* in the clang source tree for more information.


Replication of the return address
---------------------------------

In addition to the method using a modified clang, an alternative method using an
llvm FunctionPass is provided. The principle is the same but it does its work on
IR code (and the code is more obvious)

How to use:

```
/path/to/clang -emit-llvm -o code.bc code.c
/path/to/opt -load /path/to/llvm/build/lib/LLVMReplicateReturn.so -repl-return <
code.bc > codeTransformed.bc
/path/to/clang -o prog codeTramsformed.bc
```

*NOTE*: Currently the llvm.setreturnaddress intrinsic is only implemented for
 X86-based systems

*NOTE*: Currently there are 11 additional unexpected failures when running the
 llvm and clang tests. 5 of them are llvm tests. One of them could be an issue
 (check *failingTests.md* for more information).