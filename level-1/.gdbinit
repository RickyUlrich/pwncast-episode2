
set disassembly-flavor intel
set disassemble-next-line on

# call rbx
break *0x00005555555546eb

command 1
break *0x7ffff7ff402b
end

run < payload
