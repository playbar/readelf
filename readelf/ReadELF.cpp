// ReadELF.cpp : Defines the entry point for the console application.
//

//#include "stdafx.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "elf.h"
#include "dwarf2.h"

int gBaseAddr;	// start address of the whole ELF file
int gSNBaseAddr;	// start address of section name string table
int gSTRBaseAddr;	// start address of string table
int gDSTRBaseAddr;	// start address of string table in dynamic segment

ABBR_TBL_INFO gAbbrInfo;
DYNAMIC_INFO gDynamicInfo;

FILE *f_out;

static Elf32_Shdr* find_section_by_id(int id)
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr;

	ehdr = (Elf32_Ehdr *)gBaseAddr;

	shdr = (Elf32_Shdr *)(gBaseAddr + ehdr->e_shoff);
	shdr += id;

	return shdr;
}

Elf32_Shdr * elf_find_section_type( int key, Elf32_Ehdr *ehdr)
{
	int j;
	Elf32_Shdr *shdr = (Elf32_Shdr *)(ehdr->e_shoff + (char *)ehdr);
	for (j = ehdr->e_shnum; --j>=0; ++shdr) 
	{
		if (key == shdr->sh_type) 
		{
			return shdr;
		}
	}
	return NULL;
}

Elf32_Phdr * elf_find_phdr_type( int type, Elf32_Ehdr *ehdr)
{
	int j;
	Elf32_Phdr *phdr = (Elf32_Phdr *)(ehdr->e_phoff + (char *)ehdr);
	for (j = ehdr->e_phnum; --j>=0; ++phdr) 
	{
		if (type == phdr->p_type) 
		{
			return phdr;
		}
	}
	return NULL;
}

/* Returns value if return_val==1, ptr otherwise */ 
void * elf_find_dynamic(int const key, Elf32_Dyn *dynp, 
	Elf32_Ehdr *ehdr, int return_val)
{
	Elf32_Phdr *pt_text = elf_find_phdr_type(PT_LOAD, ehdr);
	unsigned tx_reloc = pt_text->p_vaddr - pt_text->p_offset;
	for (; DT_NULL!=dynp->d_tag; ++dynp) 
	{
		if (key == dynp->d_tag) 
		{
			if (return_val == 1)
				return (void *)(intptr_t)dynp->d_un.d_val;
			else
				return (void *)(dynp->d_un.d_val - tx_reloc + (char *)ehdr );
		}
	}
	return NULL;
}

int check_elf_header(Elf32_Ehdr *const ehdr)
{
	if ( !ehdr || strncmp((const char *)ehdr, ELFMAG, SELFMAG) != 0 ||  
			ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
			ehdr->e_ident[EI_VERSION] != EV_CURRENT ) 
	{
		return 1;
	}

	return 0;
}


#define ELFOSABI_NONE   0       /* UNIX System V ABI */
#define ELFOSABI_HPUX   1       /* HP-UX operating system */
#define ELFOSABI_NETBSD 2       /* NetBSD */
#define ELFOSABI_LINUX  3       /* GNU/Linux */
#define ELFOSABI_HURD   4       /* GNU/Hurd */
#define ELFOSABI_SOLARIS 6      /* Solaris */
#define ELFOSABI_AIX    7       /* AIX */
#define ELFOSABI_IRIX   8       /* IRIX */
#define ELFOSABI_FREEBSD 9      /* FreeBSD */
#define ELFOSABI_TRU64  10      /* TRU64 UNIX */
#define ELFOSABI_MODESTO 11     /* Novell Modesto */
#define ELFOSABI_OPENBSD 12     /* OpenBSD */
#define ELFOSABI_STANDALONE 255 /* Standalone (embedded) application */
#define ELFOSABI_ARM   97       /* ARM */
static void describe_elf_hdr(Elf32_Ehdr* ehdr)
{
	char *tmp, *tmp1;

	switch (ehdr->e_type) {
		case ET_NONE:	tmp = "None"; tmp1 = "NONE"; break;
		case ET_REL:	tmp = "Relocatable File"; tmp1 = "REL"; break;
		case ET_EXEC:	tmp = "Executable file"; tmp1 = "EXEC"; break;
		case ET_DYN:	tmp = "Shared object file"; tmp1 = "DYN"; break;
		case ET_CORE:	tmp = "Core file"; tmp1 = "CORE"; break;
		default:
						tmp = tmp1 = "Unknown";
	}
	fprintf(f_out, "Type:\t\t%s (%s)\n", tmp1, tmp);

	switch (ehdr->e_machine) {
		case EM_NONE:		tmp="No machine"; break;
		case EM_M32:		tmp="AT&T WE 32100"; break;
		case EM_SPARC:		tmp="SUN SPARC"; break;
		case EM_386:		tmp="Intel 80386"; break;
		case EM_68K:		tmp="Motorola m68k family"; break;
		case EM_88K:		tmp="Motorola m88k family"; break;
		case EM_860:		tmp="Intel 80860"; break;
		case EM_MIPS:		tmp="MIPS R3000 big-endian"; break;
		case EM_S370:		tmp="IBM System/370"; break;
		case EM_MIPS_RS3_LE:	tmp="MIPS R3000 little-endian"; break;
		case EM_PARISC:		tmp="HPPA"; break;
		case EM_VPP500:		tmp="Fujitsu VPP500"; break;
		case EM_SPARC32PLUS:	tmp="Sun's v8plus"; break;
		case EM_960:		tmp="Intel 80960"; break;
		case EM_PPC:		tmp="PowerPC"; break;
		case EM_PPC64:		tmp="PowerPC 64-bit"; break;
		case EM_S390:		tmp="IBM S390"; break;
		case EM_V800:		tmp="NEC V800 series"; break;
		case EM_FR20:		tmp="Fujitsu FR20"; break;
		case EM_RH32:		tmp="TRW RH-32"; break;
		case EM_RCE:		tmp="Motorola RCE"; break;
		case EM_ARM:		tmp="ARM"; break;
		case EM_FAKE_ALPHA:	tmp="Digital Alpha"; break;
		case EM_SH:			tmp="Hitachi SH"; break;
		case EM_SPARCV9:	tmp="SPARC v9 64-bit"; break;
		case EM_TRICORE:	tmp="Siemens Tricore"; break;
		case EM_ARC:		tmp="Argonaut RISC Core"; break;
		case EM_H8_300:		tmp="Hitachi H8/300"; break;
		case EM_H8_300H:	tmp="Hitachi H8/300H"; break;
		case EM_H8S:		tmp="Hitachi H8S"; break;
		case EM_H8_500:		tmp="Hitachi H8/500"; break;
		case EM_IA_64:		tmp="Intel Merced"; break;
		case EM_MIPS_X:		tmp="Stanford MIPS-X"; break;
		case EM_COLDFIRE:	tmp="Motorola Coldfire"; break;
		case EM_68HC12:		tmp="Motorola M68HC12"; break;
		case EM_MMA:		tmp="Fujitsu MMA Multimedia Accelerator"; break;
		case EM_PCP:		tmp="Siemens PCP"; break;
		case EM_NCPU:		tmp="Sony nCPU embeeded RISC"; break;
		case EM_NDR1:		tmp="Denso NDR1 microprocessor"; break;
		case EM_STARCORE:	tmp="Motorola Start*Core processor"; break;
		case EM_ME16:		tmp="Toyota ME16 processor"; break;
		case EM_ST100:		tmp="STMicroelectronic ST100 processor"; break;
		case EM_TINYJ:		tmp="Advanced Logic Corp. Tinyj emb.fam"; break;
		case EM_X86_64:		tmp="AMD x86-64 architecture"; break;
		case EM_PDSP:		tmp="Sony DSP Processor"; break;
		case EM_FX66:		tmp="Siemens FX66 microcontroller"; break;
		case EM_ST9PLUS:	tmp="STMicroelectronics ST9+ 8/16 mc"; break;
		case EM_ST7:		tmp="STmicroelectronics ST7 8 bit mc"; break;
		case EM_68HC16:		tmp="Motorola MC68HC16 microcontroller"; break;
		case EM_68HC11:		tmp="Motorola MC68HC11 microcontroller"; break;
		case EM_68HC08:		tmp="Motorola MC68HC08 microcontroller"; break;
		case EM_68HC05:		tmp="Motorola MC68HC05 microcontroller"; break;
		case EM_SVX:		tmp="Silicon Graphics SVx"; break;
		case EM_AT19:		tmp="STMicroelectronics ST19 8 bit mc"; break;
		case EM_VAX:		tmp="Digital VAX"; break;
		case EM_CRIS:		tmp="Axis Communications 32-bit embedded processor"; break;
		case EM_JAVELIN:	tmp="Infineon Technologies 32-bit embedded processor"; break;
		case EM_FIREPATH:	tmp="Element 14 64-bit DSP Processor"; break;
		case EM_ZSP:		tmp="LSI Logic 16-bit DSP Processor"; break;
		case EM_MMIX:		tmp="Donald Knuth's educational 64-bit processor"; break;
		case EM_HUANY:		tmp="Harvard University machine-independent object files"; break;
		case EM_PRISM:		tmp="SiTera Prism"; break;
		case EM_AVR:		tmp="Atmel AVR 8-bit microcontroller"; break;
		case EM_FR30:		tmp="Fujitsu FR30"; break;
		case EM_D10V:		tmp="Mitsubishi D10V"; break;
		case EM_D30V:		tmp="Mitsubishi D30V"; break;
		case EM_V850:		tmp="NEC v850"; break;
		case EM_M32R:		tmp="Mitsubishi M32R"; break;
		case EM_MN10300:	tmp="Matsushita MN10300"; break;
		case EM_MN10200:	tmp="Matsushita MN10200"; break;
		case EM_PJ:			tmp="picoJava"; break;
		default:			tmp="unknown";
	}
	fprintf(f_out, "Machine:\t%s\n", tmp);	

	switch (ehdr->e_ident[EI_CLASS]) {
		case ELFCLASSNONE: tmp = "Invalid class";  break;
		case ELFCLASS32:   tmp = "ELF32"; break;
		case ELFCLASS64:   tmp = "ELF64"; break;
		default:           tmp = "Unknown";
	}
	fprintf(f_out, "Class:\t\t%s\n", tmp);

	switch (ehdr->e_ident[EI_DATA]) {
		case ELFDATANONE:  tmp = "Invalid data encoding"; break;
		case ELFDATA2LSB:  tmp = "2's complement, little endian"; break;
		case ELFDATA2MSB:  tmp = "2's complement, big endian"; break;
		default:           tmp = "Unknown";
	}
	fprintf(f_out, "Data:\t\t%s\n", tmp);

	fprintf(f_out, "Version:\t%d %s\n", ehdr->e_ident[EI_VERSION],
			(ehdr->e_ident[EI_VERSION]==EV_CURRENT)? 
			"(current)" : "(unknown: %lx)");

	switch (ehdr->e_ident[EI_OSABI]) {
		case ELFOSABI_SYSV:       tmp ="UNIX - System V"; break;
		case ELFOSABI_HPUX:       tmp ="UNIX - HP-UX"; break;
		case ELFOSABI_NETBSD:     tmp ="UNIX - NetBSD"; break;
		case ELFOSABI_LINUX:      tmp ="UNIX - Linux"; break;
		case ELFOSABI_HURD:       tmp ="GNU/Hurd"; break;
		case ELFOSABI_SOLARIS:    tmp ="UNIX - Solaris"; break;
		case ELFOSABI_AIX:        tmp ="UNIX - AIX"; break;
		case ELFOSABI_IRIX:       tmp ="UNIX - IRIX"; break;
		case ELFOSABI_FREEBSD:    tmp ="UNIX - FreeBSD"; break;
		case ELFOSABI_TRU64:      tmp ="UNIX - TRU64"; break;
		case ELFOSABI_MODESTO:    tmp ="Novell - Modesto"; break;
		case ELFOSABI_OPENBSD:    tmp ="UNIX - OpenBSD"; break;
		case ELFOSABI_STANDALONE: tmp ="Standalone App"; break;
		case ELFOSABI_ARM:        tmp ="ARM"; break;
		default:                  tmp = "Unknown";
	}
	fprintf(f_out, "OS/ABI:\t\t%s\n", tmp);

	fprintf(f_out, "ABI Version:\t%d\n", ehdr->e_ident[EI_ABIVERSION]);
}

static void describe_one_section(Elf32_Shdr* shdr)
{
	char *tmp;

	if( shdr->sh_name == SHN_UNDEF		||
		shdr->sh_name == SHN_LORESERVE	||
		shdr->sh_name == SHN_LOPROC		||
		shdr->sh_name == SHN_HIPROC		||
		shdr->sh_name == SHN_LOOS		||
		shdr->sh_name == SHN_HIOS		||
		shdr->sh_name == SHN_ABS		||
		shdr->sh_name == SHN_COMMON		||
		shdr->sh_name == SHN_XINDEX		||
		shdr->sh_name == SHN_HIRESERVE )
	{
		fprintf(f_out, "Special section, index: %d \n", shdr->sh_name);
		return;
	}

	tmp = (char *)(gSNBaseAddr + shdr->sh_name);

	fprintf(f_out, "Section name: %s \n", tmp);
	if( !strcmp(tmp, DEBUG_ABBREV_SECTION) )
	{
		gAbbrInfo.base = shdr->sh_offset;
		gAbbrInfo.size = shdr->sh_size;
	}

	switch(shdr->sh_type)			/* Section type */
	{
		case SHT_NULL:		tmp = "NULL section!"; break;
		case SHT_PROGBITS:	tmp = "SHT_PROGBITS"; break;
		case SHT_SYMTAB:	tmp = "SHT_SYMTAB, this section hold a symbol table"; break;
		case SHT_STRTAB:	tmp = "SHT_STRTAB, this section hold a string table"; break;
		case SHT_RELA:		tmp = "SHT_RELA"; break;
		case SHT_HASH:		tmp = "SHT_HASH, this section hold a symbol hash table"; break;
		case SHT_DYNAMIC:	tmp = "SHT_DYNAMIC"; break;
		case SHT_NOTE:		tmp = "SHT_NOTE"; break;
		case SHT_NOBITS:	tmp = "SHT_NOBITS"; break;
		case SHT_REL:		tmp = "SHT_REL"; break;
		case SHT_SHLIB:		tmp = "SHT_SHLIB"; break;
		case SHT_DYNSYM:	tmp = "SHT_DYNSYM"; break;
		default:			tmp = "system reserved"; break;
	}

	fprintf(f_out, "Type: %s \n", tmp);

	fprintf(f_out, "Flags: ");
	if(shdr->sh_flags & SHF_WRITE)
	{
		fprintf(f_out, "SHF_WRITE ");
	}

	if(shdr->sh_flags & SHF_ALLOC)
	{
		fprintf(f_out, "SHF_ALLOC ");
	}

	if(shdr->sh_flags & SHF_EXECINSTR)
	{
		fprintf(f_out, "SHF_EXECINSTR ");
	}

	if((shdr->sh_flags & SHF_MASKPROC) == SHF_MASKPROC)
	{
		fprintf(f_out, "SHF_MASKPROC ");
	}
	fprintf( f_out, "\n" );

	fprintf(f_out, "Virtual addr at execution: 0x%x \n", shdr->sh_addr);	/* Section virtual addr at execution */
	fprintf(f_out, "Offset in file: 0x%x \n", shdr->sh_offset);	/* Section file offset */
	fprintf(f_out, "Size: 0x%x \n", shdr->sh_size);			/* Section size in bytes */
	fprintf(f_out, "Section header link: %d \n", shdr->sh_link);		/* Link to another section */
	fprintf(f_out, "Additional information: %d \n", shdr->sh_info);		/* Additional section information */
	fprintf(f_out, "Alignment: %d \n", shdr->sh_addralign);		/* Section alignment */
	fprintf(f_out, "Entry size if section holds table: %d \n", shdr->sh_entsize);	/* Entry size if section holds table */
}

static void describe_elf_sections(Elf32_Ehdr* ehdr)
{
	int i, offset;
	Elf32_Shdr*	 shdr;

	if( ehdr->e_shnum )
	{
		offset = ehdr->e_shoff + ehdr->e_shstrndx * ehdr->e_shentsize;
		shdr = (Elf32_Shdr *)(gBaseAddr + offset);

		gSNBaseAddr = gBaseAddr + shdr->sh_offset;		

		fprintf(f_out, "Total %d sections! \n", ehdr->e_shnum);
		shdr = (Elf32_Shdr *)(gBaseAddr + ehdr->e_shoff);
		
		for(i = 0; i <ehdr->e_shnum; i++)
		{
			fprintf(f_out, "\n ----------------%d--------------- \n", i);
			describe_one_section( shdr );
			shdr++;
		}

		fprintf(f_out, "\n ----------------end--------------- \n");
	}
	else
	{
		fprintf(f_out, "No sections! \n");
	}
}

static bool is_compile_unit(Elf32_Shdr* shdr)
{
	char *tmp;

	if( shdr->sh_name == SHN_UNDEF		||
		shdr->sh_name == SHN_LORESERVE	||
		shdr->sh_name == SHN_LOPROC		||
		shdr->sh_name == SHN_HIPROC		||
		shdr->sh_name == SHN_LOOS		||
		shdr->sh_name == SHN_HIOS		||
		shdr->sh_name == SHN_ABS		||
		shdr->sh_name == SHN_COMMON		||
		shdr->sh_name == SHN_XINDEX		||
		shdr->sh_name == SHN_HIRESERVE )
	{
		return false;
	}

	tmp = (char *)(gSNBaseAddr + shdr->sh_name);

	if( !strncmp(tmp, DEBUG_INFO_SECTION, sizeof(DEBUG_INFO_SECTION)-1) )
	{
		return true;
	}

	return false;
}

/* Output the compilation unit that appears at the beginning of the
   .debug_info section, and precedes the DIE descriptions.  */
static void output_compilation_unit_header(char *pInfo)
{
	int len = *(int *)pInfo;
	pInfo += 4;
	fprintf(f_out, "Length of Compilation Unit Info: %d \n", len);

	unsigned short ver = *(unsigned short *)pInfo;
	pInfo += 2;
	fprintf(f_out, "DWARF version number: %d \n", ver);

	int offset = *(int *)pInfo;
	pInfo += 4;
	fprintf(f_out, "Offset Into Abbrev. Section: %d \n", offset);

	unsigned char ptr_size = *(unsigned char *)pInfo;
	pInfo += 1;
	fprintf(f_out, "Pointer Size (in bytes): %d \n", ptr_size);
}

/*----------------------------------------------------
 Function name: get_abbr_entry
        Author: Jack Zhao
          Date: 2004-5-31
   Description: get a abberviation entry by abberviation-code
         Input: 
            unsigned char abbr_code
        Output: static int, absolute address of the responding abbreviation entry(whithout its code).
         Notes: 
 Update: 
 Date          Name           Description 
 ============= ============== ======================
 2004-5-31     Jack Zhao      New
----------------------------------------------------*/
int get_abbr_entry( unsigned char abbr_code )
{
	char *pt;

	pt = (char *)(gBaseAddr + gAbbrInfo.base);
	while( *(unsigned char *)pt != abbr_code )
	{
		pt++;

		/* for each abbr entry, 0x0000 is the end flag, here skip this abbr-entry by checking this flag */
		while( *(unsigned short *)pt )
		{
			pt += 2;
		}

		pt += 2;	// skip 0x0000

		if( (int)pt >= (int)(gBaseAddr + gAbbrInfo.base + gAbbrInfo.size) )
		{
			return INVALID_ADDR;
		}
	}

	if(*(unsigned char *)pt == abbr_code)
	{
		return (int)(pt+1);		// skip abbr code
	}
	
	return INVALID_ADDR;
}

/* Read an attribute value described by an attribute form.  */
char *read_attribute_value( unsigned form, char* pDest, char* info_ptr )
{
	unsigned char b_size;
	unsigned short s_size;
	unsigned long l_size;
	unsigned int bytes_read;
	char *pt;

	switch (form)
	{
		case DW_FORM_addr:
			/* FIXME: DWARF3 draft sais DW_FORM_ref_addr is offset_size.  */
		case DW_FORM_ref_addr:
			sprintf(pDest, "0x%x", *(unsigned long *)info_ptr);
			info_ptr += 4;
		  break;
		case DW_FORM_block2:
			s_size = *(unsigned short *)info_ptr;
			info_ptr += 2;
			//------------------------------------------------------------
			// Notice: Content in this block is skipped here!!!
			//------------------------------------------------------------
			info_ptr += s_size;
			break;
		case DW_FORM_block4:
			l_size = *(unsigned long *)info_ptr;
			info_ptr += 4;
			//------------------------------------------------------------
			// Notice: Content in this block is skipped here!!!
			//------------------------------------------------------------
			info_ptr += l_size;
			break;
		case DW_FORM_data2:
			sprintf(pDest, "0x%x", *(unsigned short *)info_ptr);
			info_ptr += 2;
			break;
		case DW_FORM_data4:
			sprintf(pDest, "0x%x", *(unsigned long *)info_ptr);
			info_ptr += 4;
			break;
		case DW_FORM_data8:
			sprintf(pDest, "0x%x%x", *(unsigned long *)info_ptr, *(unsigned long *)(info_ptr+4));
			info_ptr += 8;
			break;
		case DW_FORM_string:
			pt = read_string (0, info_ptr, &bytes_read);
			sprintf(pDest, "%s", pt);
			info_ptr += bytes_read;
			break;
		case DW_FORM_strp:
			sprintf(pDest, "DW_FORM_strp not support \n");
			info_ptr += 4;
			break;
		case DW_FORM_block:
			l_size = read_unsigned_leb128 (0, info_ptr, &bytes_read);
			info_ptr += bytes_read;
			//------------------------------------------------------------
			// Notice: Content in this block is skipped here!!!
			//------------------------------------------------------------
			info_ptr += l_size;
			break;
		case DW_FORM_block1:
			b_size = read_1_byte (0, info_ptr);
			info_ptr += 1;
			//------------------------------------------------------------
			// Notice: Content in this block is skipped here!!!
			//------------------------------------------------------------
			info_ptr += b_size;
			break;
		case DW_FORM_data1:
			sprintf(pDest, "0x%x", *(unsigned char *)info_ptr);
			info_ptr += 1;
			break;
		case DW_FORM_flag:
			sprintf(pDest, "0x%x", *(unsigned char *)info_ptr);
			info_ptr += 1;
			break;
		case DW_FORM_sdata:
			l_size = read_signed_leb128 (0, info_ptr, &bytes_read);
			info_ptr += bytes_read;
			break;
		case DW_FORM_udata:
			l_size = read_unsigned_leb128 (0, info_ptr, &bytes_read);
			info_ptr += bytes_read;
			break;
		case DW_FORM_ref1:
			sprintf(pDest, "0x%x", *(unsigned char *)info_ptr);
			info_ptr += 1;
			break;
		case DW_FORM_ref2:
			sprintf(pDest, "0x%x", *(unsigned short *)info_ptr);
			info_ptr += 2;
			break;
		case DW_FORM_ref4:
			sprintf(pDest, "0x%x", *(unsigned long *)info_ptr);
			info_ptr += 4;
			break;
		case DW_FORM_ref8:
			sprintf(pDest, "0x%x%x", *(unsigned long *)info_ptr, *(unsigned long *)(info_ptr+4));
			info_ptr += 8;
			break;
		case DW_FORM_ref_udata:
			read_unsigned_leb128 (0, info_ptr, &bytes_read);
			info_ptr += bytes_read;
			break;
		case DW_FORM_indirect:
			form = read_unsigned_leb128 (0, info_ptr, &bytes_read);
			info_ptr += bytes_read;
			sprintf(pDest, "DW_FORM_indirect not support \n");
		  break;
		default:
			sprintf(pDest, "Dwarf Error: Invalid or unhandled FORM value: %u.");
	}

	return info_ptr;
}

static void describe_one_compile_unit(Elf32_Shdr* shdr)
{
	char *pInfo;	// pointer to .debug_info$$$xxx section
	char *pAbbrInfo;
	unsigned char tag, has_child;
	char buf[255];
	ABBR_ITEM *pItem;

	pInfo = (char *)(gBaseAddr + shdr->sh_offset);

	output_compilation_unit_header(pInfo);
	pInfo += 11;

	unsigned char abbr_code = *pInfo++;
	pAbbrInfo = (char *)get_abbr_entry( abbr_code );
	if((int)pAbbrInfo == INVALID_ADDR)
		return;

	tag = *(unsigned char *)pAbbrInfo++;
	fprintf(f_out, "%s \n", dwarf_tag_name(tag));

	has_child = *(unsigned char *)pAbbrInfo++;
	if(has_child)
		fprintf(f_out, "Has child! \n");
	else
		fprintf(f_out, "No child! \n");

	pItem = (ABBR_ITEM *)pAbbrInfo;
	while(pItem->attr|pItem->form)
	{
		fprintf(f_out, "%s: \t", dwarf_attr_name(pItem->attr));
//		fprintf(f_out, "%s \n", dwarf_form_name(pItem->form));

		pInfo = read_attribute_value( pItem->form, buf, pInfo );
		fprintf(f_out, "%s \n", buf);

		pItem++;
	}
}

static void list_compile_units(Elf32_Ehdr* ehdr)
{
	int i;
	char *pt;
	Elf32_Shdr*	 shdr;

	if( ehdr->e_shnum )
	{
		shdr = (Elf32_Shdr *)(gBaseAddr + ehdr->e_shoff);
		
		for(i = 0; i <ehdr->e_shnum; i++)
		{
			if( is_compile_unit(shdr) )
			{
				pt = (char *)(gSNBaseAddr + shdr->sh_name + sizeof(DEBUG_INFO_SECTION));
				while( *pt == '$' )
				{
					pt++;
				}

				fprintf(f_out, "\n ----------------%s--------------- \n", pt);

				describe_one_compile_unit(shdr);
			}

			shdr++;
		}
	}
}

static void describe_one_segment(Elf32_Phdr* phdr)
{
	char *tmp;

	switch(phdr->p_type) 
	{
		case PT_NULL: tmp = "PT_NULL"; break;
		case PT_LOAD: tmp = "PT_LOAD, loadable segment"; break;
		case PT_DYNAMIC: tmp = "PT_DYNAMIC"; break;
		case PT_INTERP: tmp = "PT_INTERP"; break;
		case PT_NOTE: tmp = "PT_NOTE"; break;
		case PT_SHLIB: tmp = "PT_SHLIB"; break;
		case PT_PHDR: tmp = "PT_PHDR"; break;
		case PT_LOPROC: tmp = "PT_LOPROC/REGINFO"; break;
		case PT_HIPROC: tmp = "PT_HIPROC"; break;
		default: tmp = "PT_BOGUS"; break;
	}

	fprintf(f_out, "Type:\t%s\n", tmp);	
	fprintf(f_out, "Offset in file: 0x%x \n", phdr->p_offset);	/* Segment file offset */
	fprintf(f_out, "Virtual address: 0x%x \n", phdr->p_vaddr);	/* Segment virtual address */
	fprintf(f_out, "Physical address: 0x%x \n", phdr->p_paddr);	/* Segment physical address */
	fprintf(f_out, "Size in file: 0x%x \n", phdr->p_filesz);	/* Segment size in file */
	fprintf(f_out, "Size in memory: 0x%x \n", phdr->p_memsz);	/* Segment size in memory */
	fprintf(f_out, "Flags: ");		/* Segment flags */
	if(phdr->p_flags & PF_X)
	{
		fprintf(f_out, "PF_X ");
	}
	if(phdr->p_flags & PF_W)
	{
		fprintf(f_out, "PF_W ");
	}
	if(phdr->p_flags & PF_R)
	{
		fprintf(f_out, "PF_R ");
	}
	if((phdr->p_flags & PF_MASKPROC) == PF_MASKPROC)
	{
		fprintf(f_out, "PF_MASKPROC ");
	}
	fprintf( f_out, "\n" );
	fprintf(f_out, "Alignment: 0x%x \n", phdr->p_align);	/* Segment alignment */
}

static void describe_elf_segments(Elf32_Ehdr* ehdr)
{
	int i;
	Elf32_Phdr*	 phdr;

	if( ehdr->e_phnum )
	{
		fprintf(f_out, "\n ======================================================================== \n");
		fprintf(f_out, "\nTotal %d segments! \n", ehdr->e_phnum);
		phdr = (Elf32_Phdr *)(gBaseAddr + ehdr->e_phoff);
		
		for(i = 0; i <ehdr->e_phnum; i++)
		{
			fprintf(f_out, "\n ----------------%d--------------- \n", i);
			describe_one_segment( phdr );
			phdr++;
		}

		fprintf(f_out, "\n ----------------segment end--------------- \n");
	}
	else
	{
		fprintf(f_out, "No segment! \n");
	}
}

static void describe_one_elf_symbol(Elf32_Sym *pSym)
{
	char *tmp;
	Elf32_Shdr* shdr;

	if(gSTRBaseAddr)
	{
		fprintf(f_out, "Name:\t%s\n", (gSTRBaseAddr+pSym->st_name));	
	}
	else
	{
		fprintf(f_out, "Name:\t NULL \n");	
	}

	fprintf(f_out, "Value:\t0x%x\n", pSym->st_value);	
	fprintf(f_out, "Size:\t0x%x\n", pSym->st_size);	

	tmp = 0;
	switch( ELF32_ST_BIND(pSym->st_info) )
	{
		case STB_LOCAL:
			tmp = "STB_LOCAL";
			break;

		case STB_GLOBAL:
			if (pSym->st_shndx != SHN_UNDEF && pSym->st_shndx != SHN_COMMON)
			{
				tmp = "STB_GLOBAL";
			}
			break;

		case STB_WEAK:
			tmp = "STB_WEAK";
			break;
	}

	fprintf(f_out, "Bind:\t%s\n", tmp);	

	tmp = 0;
	switch( ELF32_ST_TYPE(pSym->st_info) )
	{
		case STT_SECTION:
			tmp = "STT_SECTION";
			break;

		case STT_FILE:
			tmp = "STT_FILE";
			break;

		case STT_FUNC:
			tmp = "STT_FUNC";
			break;

		case STT_OBJECT:
			tmp = "STT_OBJECT";
			break;
	}

	fprintf(f_out, "Type:\t%s\n", tmp);	
	fprintf(f_out, "Other:\t0x%x\n", pSym->st_other);	

	if (pSym->st_shndx == SHN_UNDEF)
	{
		fprintf(f_out, "Section index:\tSHN_UNDEF\n");	
	}
	else if (pSym->st_shndx < SHN_LORESERVE || pSym->st_shndx > SHN_HIRESERVE)
	{
		shdr = find_section_by_id( pSym->st_shndx );
		if (shdr == NULL)
		{
			fprintf(f_out, "Section index:\tError!\n");	
		}
		else
		{
			fprintf(f_out, "Section index:\t0x%x\n", pSym->st_shndx);	
		}

	}
	else if (pSym->st_shndx == SHN_ABS)
	{
		fprintf(f_out, "Section index:\tSHN_ABS\n");	
	}
	else if (pSym->st_shndx == SHN_COMMON)
	{
		fprintf(f_out, "Section index:\tSHN_COMMON\n");	
	}
	else
	{
		fprintf(f_out, "Section index:\t0x%x\n", pSym->st_shndx);	
	}
}

static void describe_elf_symbols(Elf32_Shdr* shdr)
{
	int i, num;
	Elf32_Sym*	pSym;
	Elf32_Shdr* pStrSection;

	num = shdr->sh_size / sizeof(Elf32_Sym);
	pSym = (Elf32_Sym*)(gBaseAddr + shdr->sh_offset);

	pStrSection = find_section_by_id(shdr->sh_link);
	if(pStrSection->sh_type == SHT_STRTAB)
	{
		gSTRBaseAddr = gBaseAddr + pStrSection->sh_offset;
	}
	else
	{
		gSTRBaseAddr = 	0;
	}

	fprintf(f_out, "\n ======================================================================== \n");
	fprintf(f_out, "\nTotal %d symbols! \n", num);

	for(i = 0; i < num; i++)
	{
		fprintf(f_out, "\n ----------------%d--------------- \n", i);
		describe_one_elf_symbol(pSym);
		pSym++;
	}

	fprintf(f_out, "\n ----------------symbol end--------------- \n");
}

static void list_needed_libraries(Elf32_Dyn* dynamic, char *strtab)
{
	Elf32_Dyn  *dyns;

	printf("Dependancies:\n");
	for (dyns=dynamic; dyns->d_tag!=DT_NULL; ++dyns) 
	{
		if (dyns->d_tag == DT_NEEDED) 
		{
			printf("\t%s\n", (char*)strtab + dyns->d_un.d_val);
		}
	}
}
    
static void describe_elf_interpreter(Elf32_Ehdr* ehdr)
{
	Elf32_Phdr *phdr;
	phdr = elf_find_phdr_type(PT_INTERP, ehdr);
	if (phdr) 
	{
		printf("Interpreter:\t%s\n", (char*)ehdr + phdr->p_offset);
	}
}

static void describe_dynamic_info(Elf32_Dyn* dyn)
{
	char *tmp;

	switch(dyn->d_tag)
	{
	case DT_NEEDED:		
		tmp = (char *)(gDynamicInfo.str_tbl_addr + dyn->d_un.d_val);
		fprintf(f_out, "DT_NEEDED, needed library: %s", tmp);
		break;

	case DT_PLTRELSZ:
		fprintf(f_out, "DT_PLTRELSZ, unused \n");
		break;

	case DT_PLTGOT:
		fprintf(f_out, "DT_PLTGOT, unused \n");
		break;

	case DT_HASH:
		fprintf(f_out, "DT_HASH, Hash table section offset: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_STRTAB:		
		fprintf(f_out, "DT_STRTAB, String table section offset: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_SYMTAB:		
		fprintf(f_out, "DT_SYMTAB, Symbol table section offset: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_RELA:		
		fprintf(f_out, "DT_RELA, SHT_RELA relocation section offset: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_RELASZ:		
		fprintf(f_out, "DT_RELASZ, SHT_RELA relocation section size: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_RELAENT:	
		fprintf(f_out, "DT_RELAENT, Entry size in SHT_RELA relocation section: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_STRSZ:		
		fprintf(f_out, "DT_STRSZ, String table section size: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_SYMENT:		
		fprintf(f_out, "DT_SYMENT, Entry size of ARM symbol table: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_INIT:		
		fprintf(f_out, "DT_INIT, unused \n");
		break;

	case DT_FINI:		
		fprintf(f_out, "DT_FINI, unused \n");
		break;

	case DT_SONAME:		
		tmp = (char *)(gDynamicInfo.str_tbl_addr + dyn->d_un.d_val);
		fprintf(f_out, "DT_SONAME, shared object name: %s \n", tmp);
		break;

	case DT_RPATH:		
		fprintf(f_out, "DT_RPATH, unused \n");
		break;

	case DT_SYMBOLIC:	
		fprintf(f_out, "DT_SYMBOLIC, unused \n");
		break;

	case DT_REL:		
		fprintf(f_out, "DT_REL, SHT_REL relocation section offset: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_RELSZ:		
		fprintf(f_out, "DT_RELSZ, SHT_REL relocation section size: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_RELENT:		
		fprintf(f_out, "DT_RELENT, Entry size in SHT_REL relocation section: 0x%x \n", dyn->d_un.d_val);
		break;

	case DT_PLTREL:		
		fprintf(f_out, "DT_PLTREL, unused \n");
		break;

	case DT_DEBUG:		
		fprintf(f_out, "DT_DEBUG, unused \n");
		break;

	case DT_TEXTREL:	
		fprintf(f_out, "DT_TEXTREL, unused \n");
		break;

	case DT_JMPREL:		
		fprintf(f_out, "DT_JMPREL, unused \n");
		break;

	case DT_BIND_NOW:	
		fprintf(f_out, "DT_BIND_NOW, unused \n");
		break;

	case DT_LOPROC:	
		fprintf(f_out, "DT_LOPROC, unused \n");
		break;

	case DT_HIPROC:	
		fprintf(f_out, "DT_HIPROC, unused \n");
		break;
	}
}

static void describe_elf_dynamic(Elf32_Ehdr* ehdr)
{
	Elf32_Phdr	*phdr;
	Elf32_Dyn	*dyn;

	phdr = elf_find_phdr_type( PT_DYNAMIC, ehdr);
	if(phdr)
	{
		fprintf(f_out, "\n ======================================================================== \n");

		dyn = (Elf32_Dyn *)(gBaseAddr + phdr->p_offset);
		while(dyn->d_tag != DT_NULL)
		{
			describe_dynamic_info(dyn);
			fprintf(f_out, "\n --------------------------------- \n");

			dyn++;
		}
	}

	fprintf(f_out, "\n ----------------dynamic end--------------- \n");
}	

static void describe_elf_rels(Elf32_Ehdr* ehdr)
{
	Elf32_Rel	*rel;
	int num, sym, type;

	rel = (Elf32_Rel *)gDynamicInfo.rel_tbl_addr;
	if(!rel || !gDynamicInfo.rel_entry_size)
		return;

	num = gDynamicInfo.rel_tbl_size / gDynamicInfo.rel_entry_size;

	fprintf(f_out, "\n ======================================================================== \n");
	while(num--)
	{
		sym = ELF32_R_SYM(rel->r_info);
		type = ELF32_R_TYPE(rel->r_info);
		fprintf(f_out, "0x%x: \t 0x%x \t 0x%x \n", rel->r_offset, sym, type);

		fprintf(f_out, "\n --------------------------------- \n");

		rel++;
	}

	fprintf(f_out, "\n ----------------rel end--------------- \n");
}	

static void get_dynamic_info(Elf32_Ehdr* ehdr)
{
	Elf32_Phdr	*phdr;
	Elf32_Dyn	*dyn;

	phdr = elf_find_phdr_type( PT_DYNAMIC, ehdr);
	if(phdr)
	{
		dyn = (Elf32_Dyn *)(gBaseAddr + phdr->p_offset);
		while(dyn->d_tag != DT_NULL)
		{	
			if(dyn->d_tag == DT_STRTAB)
			{
				gDynamicInfo.str_tbl_addr = gBaseAddr + (int)phdr->p_offset + dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_SYMTAB)
			{
				gDynamicInfo.sym_tbl_addr = gBaseAddr + (int)phdr->p_offset + dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_REL)
			{
				gDynamicInfo.rel_tbl_addr = gBaseAddr + (int)phdr->p_offset + dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_RELSZ)
			{
				gDynamicInfo.rel_tbl_size = dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_RELENT)
			{
				gDynamicInfo.rel_entry_size = dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_RELA)
			{
				gDynamicInfo.rela_tbl_addr = gBaseAddr + (int)phdr->p_offset + dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_RELASZ)
			{
				gDynamicInfo.rela_tbl_size = dyn->d_un.d_ptr;
			}

			if(dyn->d_tag == DT_RELAENT)
			{
				gDynamicInfo.rela_entry_size = dyn->d_un.d_ptr;
			}

			dyn++;
		}
	}
}	

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		printf("Usage: ReadELF.exe filename \n");
		return EXIT_FAILURE;
	}

	HANDLE	hFile, hMapping;
	DWORD	size, err;

	char *dynstr;
	char *thefilename = argv[1];
	
	Elf32_Ehdr *ehdr = 0;
	Elf32_Shdr *dynsec, *shdr;
	Elf32_Dyn *dynamic;

	if( !thefilename )
	{
		fprintf(stderr, "No filename specified.\n");
		exit(EXIT_FAILURE);
	}

	if ((hFile = CreateFile(thefilename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0)) == INVALID_HANDLE_VALUE)
	{
		err = GetLastError();
		puts("Open source file failed!");
		return EXIT_FAILURE;
	}

	size = GetFileSize(hFile, 0);
	if( size == 0xFFFFFFFF || size < sizeof(Elf32_Ehdr) )
		goto foo;

	if (!(hMapping = CreateFileMapping(hFile, 0, PAGE_READONLY | SEC_COMMIT, 0, 0, 0)))
	{
		puts("(Mapping source file failed!)");
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	if (!(ehdr = (Elf32_Ehdr *)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0)))
	{
		puts("(View failed!)");
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

	gBaseAddr = (int)ehdr;

	if( (f_out = fopen( "out.txt", "w" )) == NULL )
	{
		printf( "Create file 'out.txt' fail!\n" );
		UnmapViewOfFile(ehdr);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return EXIT_FAILURE;
	}

foo:
	/* Check if this looks legit */
	if (check_elf_header(ehdr)) 
	{
		fprintf(stderr, "This does not appear to be an ELF file.\n");
		UnmapViewOfFile(ehdr);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		fclose(f_out);
		return EXIT_FAILURE;
	}

	describe_elf_hdr(ehdr);
	describe_elf_sections(ehdr);
	list_compile_units(ehdr);

	describe_elf_segments(ehdr);

	get_dynamic_info(ehdr);
	describe_elf_dynamic(ehdr);
	describe_elf_rels(ehdr);

	shdr = elf_find_section_type(SHT_SYMTAB, ehdr);
	describe_elf_symbols(shdr);

	describe_elf_interpreter(ehdr);

	dynsec = elf_find_section_type(SHT_DYNAMIC, ehdr);
	if (dynsec) 
	{
		dynamic = (Elf32_Dyn*)(dynsec->sh_offset + (intptr_t)ehdr);
		dynstr = (char *)elf_find_dynamic(DT_STRTAB, dynamic, ehdr, 0);
		list_needed_libraries(dynamic, dynstr);
	}

	UnmapViewOfFile(ehdr);
	CloseHandle(hMapping);
	CloseHandle(hFile);
	fclose(f_out);
	return EXIT_SUCCESS;
}
