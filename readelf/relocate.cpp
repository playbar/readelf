//#include "stdafx.h"
#include "relocate.h"

unsigned long do_mmap_pgoff(
	struct file * file,
	unsigned long addr,
	unsigned long len,
	unsigned long prot,
	unsigned long flags,
	unsigned long pgoff)
{
	void * result;
#if 0
	struct mm_struct * mm = current->mm;
#endif
	struct mm_tblock_struct * tblock;
	unsigned int vm_flags;

	/*
	 * Get the NO_MM specific checks done first
	 */
	if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && (file)) {
		printk("MAP_SHARED not supported (cannot write mappings to disk)\n");
		return -EINVAL;
	}
	
	if ((prot & PROT_WRITE) && (flags & MAP_PRIVATE)) {
		printk("Private writable mappings not supported\n");
		return -EINVAL;
	}
	
	/*
	 *	now all the standard checks
	 */
	if (file && (!file->f_op || !file->f_op->mmap))
		return -ENODEV;

	if (PAGE_ALIGN(len) == 0)
		return addr;

	if (len > TASK_SIZE)
		return -EINVAL;

	/* offset overflow? */
	if ((pgoff + (len >> PAGE_SHIFT)) < pgoff)
		return -EINVAL;

#if 0
	/* Too many mappings? */
	if (mm->map_count > MAX_MAP_COUNT)
		return -ENOMEM;
#endif

	/* Obtain the address to map to. we verify (or select) it and ensure
	 * that it represents a valid section of the address space.
	 */
	addr = get_unmapped_area(file, addr, len, pgoff, flags);
	if (addr & ~PAGE_MASK)
		return addr;

	/* Do simple checking here so the lower-level routines won't have
	 * to. we assume access permissions have been handled by the open
	 * of the memory object, so we don't do any here.
	 */
	vm_flags = calc_vm_flags(prot,flags) /* | mm->def_flags */ | VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC;

#if 0
	/* mlock MCL_FUTURE? */
	if (vm_flags & VM_LOCKED) {
		unsigned long locked = mm->locked_vm << PAGE_SHIFT;
		locked += len;
		if (locked > current->rlim[RLIMIT_MEMLOCK].rlim_cur)
			return -EAGAIN;
	}
#endif

	/*
	 * determine the object being mapped and call the appropriate
	 * specific mapper. 
	 */

	if (file) {
		struct vm_area_struct vma;
		int error;
		
		
		if (!file->f_op)
			return -ENODEV;

		vma.vm_start = addr;
		vma.vm_end = addr + len;
		vma.vm_flags = vm_flags;
		vma.vm_offset = pgoff << PAGE_SHIFT;

#ifdef MAGIC_ROM_PTR
		/* First, try simpler routine designed to give us a ROM pointer. */

		if (file->f_op->romptr && !(prot & PROT_WRITE)) {
			error = file->f_op->romptr(file, &vma);
#ifdef DEBUG
			printk("romptr mmap returned %d, start 0x%.8x\n", error,
					vma.vm_start);
#endif
			if (!error)
				return vma.vm_start;
			else if (error != -ENOSYS)
				return error;
		} else
#endif /* MAGIC_ROM_PTR */
		/* Then try full mmap routine, which might return a RAM pointer,
		   or do something truly complicated. */
		   
		if (file->f_op->mmap) {
			error = file->f_op->mmap(file, &vma);
				   
#ifdef DEBUG
			printk("mmap mmap returned %d /%x\n", error, vma.vm_start);
#endif
			if (!error)
				return vma.vm_start;
			else if (error != -ENOSYS)
				return error;
		} else
			return -ENODEV; /* No mapping operations defined */

		/* An ENOSYS error indicates that mmap isn't possible (as opposed to
		   tried but failed) so we'll fall through to the copy. */
	}

	tblock = (struct mm_tblock_struct *)
                        kmalloc(sizeof(struct mm_tblock_struct), GFP_KERNEL);
	if (!tblock) {
		printk("Allocation of tblock for %lu byte allocation from process %d failed\n", len, current->pid);
		show_buffers();
		show_free_areas();
		return -ENOMEM;
	}

	tblock->rblock = (struct mm_rblock_struct *)
			kmalloc(sizeof(struct mm_rblock_struct), GFP_KERNEL);

	if (!tblock->rblock) {
		printk("Allocation of rblock for %lu byte allocation from process %d failed\n", len, current->pid);
		show_buffers();
		show_free_areas();
		kfree(tblock);
		return -ENOMEM;
	}

	
	result = kmalloc(len, GFP_KERNEL);
	if (!result) {
		printk("Allocation of length %lu from process %d failed\n", len,
				current->pid);
		show_buffers();
		show_free_areas();
		kfree(tblock->rblock);
		kfree(tblock);
		return -ENOMEM;
	}

	tblock->rblock->refcount = 1;
	tblock->rblock->kblock = result;
	tblock->rblock->size = len;
	
	realalloc += ksize(result);
	askedalloc += len;

#ifdef WARN_ON_SLACK	
	if ((len+WARN_ON_SLACK) <= ksize(result))
		printk("Allocation of %lu bytes from process %d has %lu bytes of slack\n", len, current->pid, ksize(result)-len);
#endif
	
	if (file) {
		int error;
		mm_segment_t old_fs = get_fs();
		set_fs(KERNEL_DS);
		error = file->f_op->read(file, (char *) result, len, &file->f_pos);
		set_fs(old_fs);
		if (error < 0) {
			kfree(result);
			kfree(tblock->rblock);
			kfree(tblock);
			return error;
		}
		if (error<len)
			memset(result+error, '\0', len-error);
	} else {
		memset(result, '\0', len);
	}

        
	realalloc += ksize(tblock);
	askedalloc += sizeof(struct mm_tblock_struct);

	realalloc += ksize(tblock->rblock);
	askedalloc += sizeof(struct mm_rblock_struct);

	tblock->next = current->mm->tblock.next;
	current->mm->tblock.next = tblock;

#ifdef DEBUG
	printk("do_mmap:\n");
	show_process_blocks();
#endif	  

	return (unsigned long)result;
}

/*
 * These are the functions used to load ELF style executables and shared
 * libraries.  There is no binary dependent code anywhere else.
 */

#define INTERPRETER_NONE 0
#define INTERPRETER_AOUT 1
#define INTERPRETER_ELF 2


static int load_elf_binary(struct linux_binprm * bprm, struct pt_regs * regs)
{
	struct file *interpreter = NULL; /* to shut gcc up */
 	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = NULL;
	unsigned int interpreter_type = INTERPRETER_NONE;
	unsigned char ibcs2_interpreter = 0;
	unsigned long error;
	struct elf_phdr * elf_ppnt, *elf_phdata;
	unsigned long elf_bss, k, elf_brk;
	int elf_exec_fileno;
	int retval, i;
	unsigned int size;
	unsigned long elf_entry, interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	struct elfhdr elf_ex;
	struct elfhdr interp_elf_ex;
  	struct exec interp_ex;
	char passed_fileno[6];
	struct files_struct *files;
	
	/* Get the exec-header */
	elf_ex = *((struct elfhdr *) bprm->buf);

	retval = -ENOEXEC;
	/* First of all, some simple consistency checks */
	if (memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	if (elf_ex.e_type != ET_EXEC && elf_ex.e_type != ET_DYN)
		goto out;
	if (!elf_check_arch(&elf_ex))
		goto out;
	if (!bprm->file->f_op||!bprm->file->f_op->mmap)
		goto out;

	/* Now read in all of the header information */

	retval = -ENOMEM;
	if (elf_ex.e_phentsize != sizeof(struct elf_phdr))
		goto out;
	if (elf_ex.e_phnum > 65536U / sizeof(struct elf_phdr))
		goto out;
	size = elf_ex.e_phnum * sizeof(struct elf_phdr);
	elf_phdata = (struct elf_phdr *) kmalloc(size, GFP_KERNEL);
	if (!elf_phdata)
		goto out;

	retval = kernel_read(bprm->file, elf_ex.e_phoff, (char *) elf_phdata, size);
	if (retval < 0)
		goto out_free_ph;
		
	files = current->files;		/* Refcounted so ok */
	if(unshare_files() < 0)
		goto out_free_ph;
	if (files == current->files) {
		put_files_struct(files);
		files = NULL;
	}

	/* exec will make our files private anyway, but for the a.out
	   loader stuff we need to do it earlier */
	   
	retval = get_unused_fd();
	if (retval < 0)
		goto out_free_fh;
	get_file(bprm->file);
	fd_install(elf_exec_fileno = retval, bprm->file);

	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	for (i = 0; i < elf_ex.e_phnum; i++) {
		if (elf_ppnt->p_type == PT_INTERP) {
			/* This is the program interpreter used for
			 * shared libraries - for now assume that this
			 * is an a.out format binary
			 */

			retval = -ENOMEM;
			if (elf_ppnt->p_filesz > PATH_MAX)
				goto out_free_file;
			elf_interpreter = (char *) kmalloc(elf_ppnt->p_filesz,
							   GFP_KERNEL);
			if (!elf_interpreter)
				goto out_free_file;

			retval = kernel_read(bprm->file, elf_ppnt->p_offset,
					   elf_interpreter,
					   elf_ppnt->p_filesz);
			if (retval < 0)
				goto out_free_interp;
			/* If the program interpreter is one of these two,
			 * then assume an iBCS2 image. Otherwise assume
			 * a native linux image.
			 */
			if (strcmp(elf_interpreter,"/usr/lib/libc.so.1") == 0 ||
			    strcmp(elf_interpreter,"/usr/lib/ld.so.1") == 0)
				ibcs2_interpreter = 1;
#if 0
			printk("Using ELF interpreter %s\n", elf_interpreter);
#endif

			SET_PERSONALITY(elf_ex, ibcs2_interpreter);

			interpreter = open_exec(elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;
			retval = kernel_read(interpreter, 0, bprm->buf, BINPRM_BUF_SIZE);
			if (retval < 0)
				goto out_free_dentry;

			/* Get the exec headers */
			interp_ex = *((struct exec *) bprm->buf);
			interp_elf_ex = *((struct elfhdr *) bprm->buf);
			break;
		}
		elf_ppnt++;
	}

	/* Some simple consistency checks for the interpreter */
	if (elf_interpreter) {
		interpreter_type = INTERPRETER_ELF | INTERPRETER_AOUT;

		/* Now figure out which format our binary is */
		if ((N_MAGIC(interp_ex) != OMAGIC) &&
		    (N_MAGIC(interp_ex) != ZMAGIC) &&
		    (N_MAGIC(interp_ex) != QMAGIC))
			interpreter_type = INTERPRETER_ELF;

		if (memcmp(interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
			interpreter_type &= ~INTERPRETER_ELF;

		retval = -ELIBBAD;
		if (!interpreter_type)
			goto out_free_dentry;

		/* Make sure only one type was selected */
		if ((interpreter_type & INTERPRETER_ELF) &&
		     interpreter_type != INTERPRETER_ELF) {
	     		// FIXME - ratelimit this before re-enabling
			// printk(KERN_WARNING "ELF: Ambiguous type, using ELF\n");
			interpreter_type = INTERPRETER_ELF;
		}
	} else {
		/* Executables without an interpreter also need a personality  */
		SET_PERSONALITY(elf_ex, ibcs2_interpreter);
	}

	/* OK, we are done with that, now set up the arg stuff,
	   and then start this sucker up */

	if (!bprm->sh_bang) {
		char * passed_p;

		if (interpreter_type == INTERPRETER_AOUT) {
		  sprintf(passed_fileno, "%d", elf_exec_fileno);
		  passed_p = passed_fileno;

		  if (elf_interpreter) {
		    retval = copy_strings_kernel(1,&passed_p,bprm);
			if (retval)
				goto out_free_dentry; 
		    bprm->argc++;
		  }
		}
	}

	/* Flush all traces of the currently running executable */
	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;

	/* Discard our unneeded old files struct */
	if (files) {
		steal_locks(files);
		put_files_struct(files);
		files = NULL;
	}

	/* OK, This is the point of no return */
	current->mm->start_data = 0;
	current->mm->end_data = 0;
	current->mm->end_code = 0;
	current->mm->mmap = NULL;
	current->flags &= ~PF_FORKNOEXEC;
	elf_entry = (unsigned long) elf_ex.e_entry;

	/* Do this so that we can load the interpreter, if need be.  We will
	   change some of these later */
	current->mm->rss = 0;
	retval = setup_arg_pages(bprm);
	if (retval < 0) {
		send_sig(SIGKILL, current, 0);
		return retval;
	}
	
	current->mm->start_stack = bprm->p;

	/* Now we do a little grungy work by mmaping the ELF image into
	   the correct location in memory.  At this point, we assume that
	   the image should be loaded at fixed address, not at a variable
	   address. */

	for(i = 0, elf_ppnt = elf_phdata; i < elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long vaddr;

		if (elf_ppnt->p_type != PT_LOAD)
			continue;

		if (unlikely (elf_brk > elf_bss)) {
			unsigned long nbyte;
	            
			/* There was a PT_LOAD segment with p_memsz > p_filesz
			   before this one. Map anonymous pages, if needed,
			   and clear the area.  */
			set_brk (elf_bss + load_bias, elf_brk + load_bias);
			nbyte = ELF_PAGEOFFSET(elf_bss);
			if (nbyte) {
				nbyte = ELF_MIN_ALIGN - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				clear_user((void *) elf_bss + load_bias, nbyte);
			}
		}

		if (elf_ppnt->p_flags & PF_R) elf_prot |= PROT_READ;
		if (elf_ppnt->p_flags & PF_W) elf_prot |= PROT_WRITE;
		if (elf_ppnt->p_flags & PF_X) elf_prot |= PROT_EXEC;

		elf_flags = MAP_PRIVATE|MAP_DENYWRITE|MAP_EXECUTABLE;

		vaddr = elf_ppnt->p_vaddr;
		if (elf_ex.e_type == ET_EXEC || load_addr_set) {
			elf_flags |= MAP_FIXED;
		} else if (elf_ex.e_type == ET_DYN) {
			/* Try and get dynamic programs out of the way of the default mmap
			   base, as well as whatever program they might try to exec.  This
		           is because the brk will follow the loader, and is not movable.  */
			load_bias = ELF_PAGESTART(ELF_ET_DYN_BASE - vaddr);
		}

		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt, elf_prot, elf_flags);
		if (BAD_ADDR(error))
			continue;

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (elf_ex.e_type == ET_DYN) {
				load_bias += error -
				             ELF_PAGESTART(load_bias + vaddr);
				load_addr += load_bias;
			}
		}
		k = elf_ppnt->p_vaddr;
		if (k < start_code) start_code = k;
		if (start_data < k) start_data = k;

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & PF_X) && end_code <  k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk)
			elf_brk = k;
	}

	elf_entry += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;

	if (elf_interpreter) {
		if (interpreter_type == INTERPRETER_AOUT)
			elf_entry = load_aout_interp(&interp_ex,
						     interpreter);
		else
			elf_entry = load_elf_interp(&interp_elf_ex,
						    interpreter,
						    &interp_load_addr);
		if (BAD_ADDR(elf_entry)) {
			printk(KERN_ERR "Unable to load interpreter\n");
			send_sig(SIGSEGV, current, 0);
			retval = -ENOEXEC; /* Nobody gets to see this, but.. */
			goto out_free_dentry;
		}

		allow_write_access(interpreter);
		fput(interpreter);
		kfree(elf_interpreter);
	}

	kfree(elf_phdata);

	if (interpreter_type != INTERPRETER_AOUT)
		sys_close(elf_exec_fileno);

	set_binfmt(&elf_format);

	compute_creds(bprm);
	current->flags &= ~PF_FORKNOEXEC;
	bprm->p = (unsigned long)
	  create_elf_tables((char *)bprm->p,
			bprm->argc,
			bprm->envc,
			&elf_ex,
			load_addr, load_bias,
			interp_load_addr,
			(interpreter_type == INTERPRETER_AOUT ? 0 : 1));
	/* N.B. passed_fileno might not be initialized? */
	if (interpreter_type == INTERPRETER_AOUT)
		current->mm->arg_start += strlen(passed_fileno) + 1;
	current->mm->start_brk = current->mm->brk = elf_brk;
	current->mm->end_code = end_code;
	current->mm->start_code = start_code;
	current->mm->start_data = start_data;
	current->mm->end_data = end_data;
	current->mm->start_stack = bprm->p;

	/* Calling set_brk effectively mmaps the pages that we need
	 * for the bss and break sections
	 */
	set_brk(elf_bss, elf_brk);

	padzero(elf_bss);

#if 0
	printk("(start_brk) %lx\n" , (long) current->mm->start_brk);
	printk("(end_code) %lx\n" , (long) current->mm->end_code);
	printk("(start_code) %lx\n" , (long) current->mm->start_code);
	printk("(start_data) %lx\n" , (long) current->mm->start_data);
	printk("(end_data) %lx\n" , (long) current->mm->end_data);
	printk("(start_stack) %lx\n" , (long) current->mm->start_stack);
	printk("(brk) %lx\n" , (long) current->mm->brk);
#endif

	if (current->personality & MMAP_PAGE_ZERO) {
		/* Why this, you ask???  Well SVr4 maps page 0 as read-only,
		   and some applications "depend" upon this behavior.
		   Since we do not have the power to recompile these, we
		   emulate the SVr4 behavior.  Sigh.  */
		/* N.B. Shouldn't the size here be PAGE_SIZE?? */
		down_write(&current->mm->mmap_sem);
		error = do_mmap(NULL, 0, 4096, PROT_READ | PROT_EXEC,
				MAP_FIXED | MAP_PRIVATE, 0);
		up_write(&current->mm->mmap_sem);
	}

#ifdef ELF_PLAT_INIT
	/*
	 * The ABI may specify that certain registers be set up in special
	 * ways (on i386 %edx is the address of a DT_FINI function, for
	 * example.  This macro performs whatever initialization to
	 * the regs structure is required.
	 */
	ELF_PLAT_INIT(regs);
#endif

	start_thread(regs, elf_entry, bprm->p);
	if (current->ptrace & PT_PTRACED)
		send_sig(SIGTRAP, current, 0);
	retval = 0;
out:
	return retval;

	/* error cleanup */
out_free_dentry:
	allow_write_access(interpreter);
	fput(interpreter);
out_free_interp:
	if (elf_interpreter)
		kfree(elf_interpreter);
out_free_file:
	sys_close(elf_exec_fileno);
out_free_fh:
	if (files) {
		put_files_struct(current->files);
		current->files = files;
	}
out_free_ph:
	kfree(elf_phdata);
	goto out;
}

