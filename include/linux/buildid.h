/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
#ifndef _ORBPF_LINUX_BUILDID_H
#define _ORBPF_LINUX_BUILDID_H

#include <linux/pagemap.h>

#define BUILD_ID_SIZE_MAX 20
#define BUILD_ID 3





static inline int parse_build_id(void *page_addr,
				 unsigned char *build_id,
				 __u32 *size,
				 void *note_start,
				 Elf32_Word note_size)
{
	Elf32_Word note_offs = 0, new_offs;

	 
	if (note_start < page_addr || note_start + note_size < note_start)
		return -EINVAL;

	 
	if (note_start + note_size > page_addr + PAGE_SIZE)
		return -EINVAL;

	while (note_offs + sizeof(Elf32_Nhdr) < note_size) {
		Elf32_Nhdr *nhdr = (Elf32_Nhdr *)(note_start + note_offs);

		if (nhdr->n_type == BUILD_ID &&
		    nhdr->n_namesz == sizeof("GNU") &&
		    nhdr->n_descsz > 0 &&
		    nhdr->n_descsz <= BUILD_ID_SIZE_MAX) {
			memcpy(build_id,
			       note_start + note_offs +
			       ALIGN(sizeof("GNU"), 4) + sizeof(Elf32_Nhdr),
			       nhdr->n_descsz);
			memset(build_id + nhdr->n_descsz, 0,
			       BUILD_ID_SIZE_MAX - nhdr->n_descsz);
			if (size)
				*size = nhdr->n_descsz;
			return 0;
		}
		new_offs = note_offs + sizeof(Elf32_Nhdr) +
			ALIGN(nhdr->n_namesz, 4) + ALIGN(nhdr->n_descsz, 4);
		if (new_offs <= note_offs)   
			break;
		note_offs = new_offs;
	}
	return -EINVAL;
}

 
static inline int get_build_id_32(void *page_addr, unsigned char *build_id,
				  __u32 *size)
{
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)page_addr;
	Elf32_Phdr *phdr;
	int i;

	 
	if (ehdr->e_phnum >
	    (PAGE_SIZE - sizeof(Elf32_Ehdr)) / sizeof(Elf32_Phdr))
		return -EINVAL;

	phdr = (Elf32_Phdr *)(page_addr + sizeof(Elf32_Ehdr));

	for (i = 0; i < ehdr->e_phnum; ++i) {
		if (phdr[i].p_type == PT_NOTE &&
		    !parse_build_id(page_addr, build_id, size,
				    page_addr + phdr[i].p_offset,
				    phdr[i].p_filesz))
			return 0;
	}
	return -EINVAL;
}

 
static inline int get_build_id_64(void *page_addr, unsigned char *build_id,
				  __u32 *size)
{
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)page_addr;
	Elf64_Phdr *phdr;
	int i;

	 
	if (ehdr->e_phnum >
	    (PAGE_SIZE - sizeof(Elf64_Ehdr)) / sizeof(Elf64_Phdr))
		return -EINVAL;

	phdr = (Elf64_Phdr *)(page_addr + sizeof(Elf64_Ehdr));

	for (i = 0; i < ehdr->e_phnum; ++i) {
		if (phdr[i].p_type == PT_NOTE &&
		    !parse_build_id(page_addr, build_id, size,
				    page_addr + phdr[i].p_offset,
				    phdr[i].p_filesz))
			return 0;
	}
	return -EINVAL;
}









static inline int build_id_parse(struct vm_area_struct *vma,
				 unsigned char *build_id, __u32 *size)
{
	Elf32_Ehdr *ehdr;
	struct page *page;
	void *page_addr;
	int ret;

	 
	if (!vma->vm_file)
		return -EINVAL;

	page = find_get_page(vma->vm_file->f_mapping, 0);
	if (!page)
		return -EFAULT;	 

	ret = -EINVAL;
	page_addr = kmap_atomic(page);
	ehdr = (Elf32_Ehdr *)page_addr;

	 
	if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0)
		goto out;

	 
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN)
		goto out;

	if (ehdr->e_ident[EI_CLASS] == ELFCLASS32)
		ret = get_build_id_32(page_addr, build_id, size);
	else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64)
		ret = get_build_id_64(page_addr, build_id, size);
out:
	kunmap_atomic(page_addr);
	put_page(page);
	return ret;
}
#endif