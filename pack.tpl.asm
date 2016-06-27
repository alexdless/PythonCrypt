use32
    pshufw mm1, mm2, 10
    emms
    mov ah, 46
    sahf
    je Exit
    mov eax,11b
	    xor edx,edx
	    mov gs,ax
    @@:
	    mov dx,gs
	    shr edx,1
	jc @b
	mov gs,ax
	mov ax,gs
	lea eax,[eax + edx + ({{ go-0x10 }} - 11b)]
	add eax, 10h
	jmp eax
	jmp Exit
	nop
    Exit:
    push 0
    call dword [{{ imports["ExitProcess"] }}]