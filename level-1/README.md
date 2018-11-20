

## x64 calling convention
RDI, RSI, RDX, RCX, R8, R9

## amd64 system calling convention
%rdi	%rsi	%rdx	%r10	%r8	%r9

## Reversing of code
Same as `level-0` but this time all bytes with value of `0x48` are
replaced with `0xff`

## Solution
Replace `0x48` with `0x49` in payload.  This is because of unsigned mov
versus signed mov instructions.
