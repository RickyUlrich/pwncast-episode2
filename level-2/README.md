
## x64 calling convention
RDI, RSI, RDX, RCX, R8, R9

## Reverse engineering of code
```
# global variable
char *executable_buffer_ptr;

# play_the_game - 0x970
char local_fh
int *local_10h

executable_buffer_ptr = mmap(0, 0x1000, 7, 0x22, i -1, 0)

printf("I have a pointer %p\n", executable_buffer_ptr)

while (true) {
	read(0, &local_fh, 1)
	// absolute arbitrary 1 byte write
	if (local_fh == 1) {
		read(0, &local_10h, 8)
		read(0, &local_fh, 1)
                *local_10h = local_fh

	// absolute arbitrary 1 byte leak
	} else if (local_fh == 2) {
		read(0, &local_10h, 8)
		write(1, local_10h, 1)

	// absolute arbitrary call
	} else if (local_fh == 3) {
		read(0, &local_10h, 8)
		local_10h();
	} else {
		break;
        }
}
```
