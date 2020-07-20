
# generated memory dumps of level 3 memory like thisj
"""
(gdb) dump binary memory memory_0x555555554000 0x555555554000 0x555555555000
(gdb) dump binary memory memory_0x555555754000 0x555555754000 0x555555755000
(gdb) dump binary memory memory_0x555555755000 0x555555755000 0x555555756000
"""
mem1 = open("memory_0x555555554000", "rb").read()
mem2 = open("memory_0x555555754000", "rb").read()
mem3 = open("memory_0x555555755000", "rb").read()
