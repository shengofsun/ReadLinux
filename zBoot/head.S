/*
 *  linux/boot/head.S
 *
 *  Copyright (C) 1991, 1992, 1993  Linus Torvalds
 */

/*
 *  head.S contains the 32-bit startup code.
 *
 * NOTE!!! Startup happens at absolute address 0x00001000, which is also where
 * the page directory will exist. The startup code will be overwritten by
 * the page directory.
 *
 * Page 0 is deliberately kept safe, since System Management Mode code in 
 * laptops may need to access the BIOS data stored there.  This is also
 * useful for future device drivers that either access the BIOS via VM86 
 * mode.
 */
.text

#include <linux/segment.h>

	/* 从setup.s跳转过来的第一行代码 位于0x1000处 */
startup_32:
	cld
	cli
	movl $(KERNEL_DS),%eax
	mov %ax,%ds
	mov %ax,%es
	mov %ax,%fs
	mov %ax,%gs

	/* stack_start是定义在kernel/sched.c中的变量，c语言在编译时会做变量修饰，会在变量名前加_，
	所以在汇编调用的时候，就变成了_stack_start */
	/* 该指令执行完成后，ss变成KERNEL_DS，基地址为0，大小为8MB。
	esp的指向kernel/sched.c中user_stack数组的末端，大小为1KB */
	lss _stack_start,%esp
	xorl %eax,%eax
1:	incl %eax		# check that A20 really IS enabled
	movl %eax,0x000000	# loop forever if it isn't
	cmpl %eax,0x100000
	je 1b
/*
 * Initialize eflags.  Some BIOS's leave bits like NT set.  This would
 * confuse the debugger if this code is traced.
 * XXX - best to initialize before switching to protected mode.
 */
	pushl $0
	popfl
/*
 * Clear BSS
 */
	/* edata, end, _edata, _end是编译器定义的变量。
	edata表示data的下一个字节，即bss的开始；end表示bss结束后的下一个字节。
	可参看http://linux.die.net/man/3/edata */
	xorl %eax,%eax
	movl $__edata,%edi
	movl $__end,%ecx
	subl %edi,%ecx
	cld
	rep
	stosb /* 将al放入es:edi中，eax前面已经清零了 */
/*
 * Do the decompression, and jump to the new kernel..
 */
	call _decompress_kernel /* 调用misc.c下的decompress_kernel, 解压到0x100000处*/
	ljmp $(KERNEL_CS), $0x100000 /* 跳转过去，第一行代码见boot/head.S */
