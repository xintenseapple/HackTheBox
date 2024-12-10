exploit: exploit.o
	ld -e exploit -o $@ $?

exploit.o: exploit.asm
	nasm -f elf64 -g -F dwarf -o $@ $?

clean:
	rm exploit