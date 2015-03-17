/*
 *  linux/fs/file_table.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/mm.h>

/* 这个文件在修改这两个全局变量的时候为什么不关中断。我完全想不通 */
/* file_struct在全局通过file_table.c模块分配. first_file为双向循环链表的头指针
 * 通过kmalloc模块分配的file_struct会全部串在first_file链表中，而不会删除。区分
 * 结构是否可用是通过file->f_count来判断的 */
struct file * first_file;
int nr_files = 0;

static void insert_file_free(struct file *file)
{
	file->f_next = first_file;
	file->f_prev = first_file->f_prev;
	file->f_next->f_prev = file;
	file->f_prev->f_next = file;
	first_file = file;
}

static void remove_file_free(struct file *file)
{
	if (first_file == file)
		first_file = first_file->f_next;
	if (file->f_next)
		file->f_next->f_prev = file->f_prev;
	if (file->f_prev)
		file->f_prev->f_next = file->f_next;
	file->f_next = file->f_prev = NULL;
}

static void put_last_free(struct file *file)
{
	remove_file_free(file);
	file->f_prev = first_file->f_prev;
	file->f_prev->f_next = file;
	file->f_next = first_file;
	file->f_next->f_prev = file;
}

void grow_files(void)
{
	struct file * file;
	int i;

	file = (struct file *) get_free_page(GFP_KERNEL);

	if (!file)
		return;

	nr_files+=i= PAGE_SIZE/sizeof(struct file);

	/* 这代码写的不知道该怎么吐槽。C语言是精简。
	 * 但是编译成汇编一条指令也不会少，还增加了阅读难度
	 * 按照C右结合的原则，右边的=优先级是高于左边的 
	 * 强烈反对这样炫技式的编程习惯 */
	if (!first_file)
		file->f_next = file->f_prev = first_file = file++, i--;

	for (; i ; i--)
		insert_file_free(file++);
}

unsigned long file_table_init(unsigned long start, unsigned long end)
{
	first_file = NULL;
	return start;
}

/* file_struct其实就是一个最大为1024的动态扩展的线性表 */
struct file * get_empty_filp(void)
{
	int i;
	struct file * f;

	if (!first_file)
		grow_files();
repeat:
	for (f = first_file, i=0; i < nr_files; i++, f = f->f_next)
		if (!f->f_count) {
			/* 这里先remove再放回来的原因就是为了用memset */
			remove_file_free(f);
			memset(f,0,sizeof(*f));
			put_last_free(f);
			f->f_count = 1;
			return f;
		}

	/* NR_FILE限定了内核维护的最多file_struct个数，现在为1024 */
	if (nr_files < NR_FILE) {
		grow_files();
		goto repeat;
	}
	return NULL;
}
