#ifndef __ARM_H__
#define __ARM_H__

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_ARM_RELEXEC     0x01
#define EF_ARM_HASENTRY    0x02
#define EF_ARM_INTERWORK   0x04
#define EF_ARM_APCS_26     0x08
#define EF_ARM_APCS_FLOAT  0x10
#define EF_ARM_PIC         0x20
#define EF_ARM_ALIGN8	   0x40		/* 8-bit structure alignment is in use.  */
#define EF_ARM_NEW_ABI     0x80
#define EF_ARM_OLD_ABI     0x100
#define EF_ARM_SOFT_FLOAT  0x200
#define EF_ARM_VFP_FLOAT   0x400

/* Other constants defined in the ARM ELF spec. version B-01.  */
#define EF_ARM_SYMSARESORTED		0x04	/* NB conflicts with EF_INTERWORK */
#define EF_ARM_DYNSYMSUSESEGIDX		0x08	/* NB conflicts with EF_APCS26 */
#define EF_ARM_MAPSYMSFIRST			0x10	/* NB conflicts with EF_APCS_FLOAT */
#define EF_ARM_EABIMASK				0xFF000000

#define EF_ARM_EABI_VERSION(flags)	((flags) & EF_ARM_EABIMASK)
#define EF_ARM_EABI_UNKNOWN			0x00000000
#define EF_ARM_EABI_VER1			0x01000000
#define EF_ARM_EABI_VER2			0x02000000

/* Local aliases for some flags to match names used by COFF port.  */
#define F_INTERWORK	   EF_ARM_INTERWORK
#define F_APCS26	   EF_ARM_APCS_26
#define F_APCS_FLOAT   EF_ARM_APCS_FLOAT
#define F_PIC          EF_ARM_PIC
#define F_SOFT_FLOAT   EF_ARM_SOFT_FLOAT
#define F_VFP_FLOAT	   EF_ARM_VFP_FLOAT

/* Additional symbol types for Thumb.  */
#define STT_ARM_TFUNC      STT_LOPROC   /* A Thumb function.  */
#define STT_ARM_16BIT      STT_HIPROC   /* A Thumb label.  */

/* ARM-specific values for sh_flags.  */
#define SHF_ENTRYSECT      0x10000000   /* Section contains an entry point.  */
#define SHF_COMDEF         0x80000000   /* Section may be multiply defined in the input to a link step.  */

/* ARM-specific program header flags.  */
#define PF_ARM_SB          0x10000000   /* Segment contains the location addressed by the static base.  */
#define PF_ARM_PI          0x20000000   /* Segment is position-independent.  */
#define PF_ARM_ABS         0x40000000   /* Segment must be loaded at its base address.  */

/* Relocation types.  */
#define R_ARM_NONE             0
#define R_ARM_PC24             1
#define R_ARM_ABS32            2
#define R_ARM_REL32            3
#define R_ARM_PC13             4
#define R_ARM_ABS16            5
#define R_ARM_ABS12            6
#define R_ARM_THM_ABS5         7
#define R_ARM_ABS8             8
#define R_ARM_SBREL32          9
#define R_ARM_THM_PC22        10
#define R_ARM_THM_PC8         11
#define R_ARM_AMP_VCALL9      12
#define R_ARM_SWI24           13
#define R_ARM_THM_SWI8        14
#define R_ARM_XPC25           15
#define R_ARM_THM_XPC22       16

#define R_ARM_COPY            20   /* Copy symbol at runtime.  */
#define R_ARM_GLOB_DAT        21   /* Create GOT entry.  */
#define R_ARM_JUMP_SLOT       22   /* Create PLT entry.  */
#define R_ARM_RELATIVE        23   /* Adjust by program base.  */
#define R_ARM_GOTOFF          24   /* 32 bit offset to GOT.  */
#define R_ARM_GOTPC           25   /* 32 bit PC relative offset to GOT.  */
#define R_ARM_GOT32           26   /* 32 bit GOT entry.  */
#define R_ARM_PLT32           27   /* 32 bit PLT address.  */

#define FIRST_INVALID_RELOC1	28
#define LAST_INVALID_RELOC1		31
#define R_ARM_ALU_PCREL7_0		32
#define R_ARM_ALU_PCREL15_8		33
#define R_ARM_ALU_PCREL23_15	34
#define R_ARM_LDR_SBREL11_0		35
#define R_ARM_ALU_SBREL19_12	36
#define R_ARM_ALU_SBREL27_20	37
#define FIRST_INVALID_RELOC2	38
#define LAST_INVALID_RELOC2		99
#define R_ARM_GNU_VTENTRY		100		/* Record C++ vtable entry */		
#define R_ARM_GNU_VTINHERIT		101		/* Record C++ member usage */
#define R_ARM_THM_PC11			102		/* Cygnus extension to abi: Thumb unconditional branch.  */
#define R_ARM_THM_PC9			103		/* Cygnus extension to abi: Thumb conditional branch.  */
#define FIRST_INVALID_RELOC3	104
#define LAST_INVALID_RELOC3		248
#define R_ARM_RXPC25			249

#define R_ARM_RSBREL32			250
#define R_ARM_THM_RPC22			251
#define R_ARM_RREL32			252
#define R_ARM_RABS32			253
#define R_ARM_RPC24				254
#define R_ARM_RBASE				255

#endif /*__ARM_H__*/