#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <asm/uaccess.h>

#if defined(CONFIG_CPU_LOONGSON3) || defined(CONFIG_CPU_LOONGSON2H)
#include <boot_param.h>
#endif

extern struct proc_dir_entry *proc_efi;
#if defined(CONFIG_CPU_LOONGSON3) || defined(CONFIG_CPU_LOONGSON2H)
extern unsigned long smbios_addr;
#endif
extern unsigned int pmon_smbios;

static int show_systab(struct seq_file *m, void *v)
{
#if defined(CONFIG_CPU_LOONGSON3) || defined(CONFIG_CPU_LOONGSON2H)
	seq_printf(m, "SMBIOS=0x%lx\n", smbios_addr);
#endif
	return 0;
}

static void *systab_start(struct seq_file *m, loff_t *pos)
{
	unsigned long i = *pos;

	return i ? NULL : (void *)0x1;
}

static void *systab_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return systab_start(m, pos);
}

static void systab_stop(struct seq_file *m, void *v)
{
}

const struct seq_operations systab_op = {
	.start	= systab_start,
	.next	= systab_next,
	.stop	= systab_stop,
	.show	= show_systab,
};


static int systab_open(struct inode *inode, struct file *file)

{
	return seq_open(file, &systab_op);
}

static const struct file_operations proc_systab_operations = {
	.open		= systab_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init proc_systab_init(void)
{
	if(pmon_smbios == 0)
		return 0;
	else
		proc_create("systab", 0, proc_efi, &proc_systab_operations);
	return 0;
}

module_init(proc_systab_init);
