#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

struct proc_dir_entry *proc_efi;
extern unsigned int pmon_smbios;

/**
  * efi_init_procfs - Create efi in procfs
  */
int __init efi_init_procfs(void)
{
	if(pmon_smbios == 0)
		return 0;
	else
	{
		proc_efi = proc_mkdir("efi", NULL);
		if(!proc_efi)
			return -ENOMEM;
		else
			return 0;
	}
}

/**
  * efi_exit_procfs -Remove efi from procfs
  */
void efi_exit_procfs(void)
{
	if(pmon_smbios == 0)
		return ;
	else
	remove_proc_entry("efi", NULL);
}

static int __init init_efi(void)
{
	int error;
	if(pmon_smbios == 0)
		return 0;
	else
		error = efi_init_procfs();
	
	return error;
}

static void __init exit_efi(void)
{
	if(pmon_smbios == 0)
		return ;
	else
		efi_exit_procfs();
}

subsys_initcall(init_efi);
module_exit(exit_efi);
