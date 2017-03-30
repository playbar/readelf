#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "bfd.h"

/* We use a macro to initialize the static asymbol structures because
   traditional C does not permit us to initialize a union member while
   gcc warns if we don't initialize it.  */
 /* the_bfd, name, value, attr, section [, udata] */
//#ifdef __STDC__
//#define GLOBAL_SYM_INIT(NAME, SECTION) { 0, NAME, 0, BSF_SECTION_SYM, (asection *) SECTION, { 0 }}
//#else
#define GLOBAL_SYM_INIT(NAME, SECTION) { 0, NAME, 0, BSF_SECTION_SYM, (asection *) SECTION }
//#endif

/* These symbols are global, not specific to any BFD.  Therefore, anything
   that tries to change them is broken, and should be repaired.  */

static const asymbol global_syms[] =
{
  GLOBAL_SYM_INIT (BFD_COM_SECTION_NAME, &bfd_com_section),
  GLOBAL_SYM_INIT (BFD_UND_SECTION_NAME, &bfd_und_section),
  GLOBAL_SYM_INIT (BFD_ABS_SECTION_NAME, &bfd_abs_section),
  GLOBAL_SYM_INIT (BFD_IND_SECTION_NAME, &bfd_ind_section)
};

#define STD_SECTION(SEC, FLAGS, SYM, NAME, IDX)				\
  const asymbol * const SYM = (asymbol *) &global_syms[IDX]; 		\
  const asection SEC = 							\
    /* name, id,  index, next, flags, user_set_vma, reloc_done,      */	\
    { NAME,  IDX, 0,     NULL, FLAGS, 0,            0,			\
									\
    /* linker_mark, linker_has_input, gc_mark, segment_mark,         */	\
       0,           0,                1,       0,			\
									\
    /* vma, lma, _cooked_size, _raw_size,                            */	\
       0,   0,   0,            0,					\
									\
    /* output_offset, output_section,      alignment_power,          */	\
       0,             (struct sec *) &SEC, 0,				\
									\
    /* relocation, orelocation, reloc_count, filepos, rel_filepos,   */	\
       NULL,       NULL,        0,           0,       0,		\
									\
    /* line_filepos, userdata, contents, lineno, lineno_count,       */	\
       0,            NULL,     NULL,     NULL,   0,			\
									\
    /* entsize, comdat, moving_line_filepos,                         */	\
       0,       NULL,   0,						\
									\
    /* target_index, used_by_bfd, constructor_chain, owner,          */	\
       0,            NULL,        NULL,              NULL,		\
									\
    /* symbol,                                                       */	\
       (struct symbol_cache_entry *) &global_syms[IDX],			\
									\
    /* symbol_ptr_ptr,                                               */	\
       (struct symbol_cache_entry **) &SYM,				\
									\
    /* link_order_head, link_order_tail                              */	\
       NULL,            NULL						\
    }

STD_SECTION (bfd_com_section, SEC_IS_COMMON, bfd_com_symbol,
	     BFD_COM_SECTION_NAME, 0);
STD_SECTION (bfd_und_section, 0, bfd_und_symbol, BFD_UND_SECTION_NAME, 1);
STD_SECTION (bfd_abs_section, 0, bfd_abs_symbol, BFD_ABS_SECTION_NAME, 2);
STD_SECTION (bfd_ind_section, 0, bfd_ind_symbol, BFD_IND_SECTION_NAME, 3);
#undef STD_SECTION

struct section_hash_entry
{
  struct bfd_hash_entry root;
  asection section;
};

#define section_hash_lookup(table, string, create, copy) \
  ((struct section_hash_entry *) \
   bfd_hash_lookup ((table), (string), (create), (copy)))

/* Initializes a new section.  NEWSECT->NAME is already set.  */

static asection *bfd_section_init PARAMS ((bfd *, asection *));

static asection *bfd_section_init ( bfd *abfd, asection *newsect )
{
  static int section_id = 0x10;  /* id 0 to 3 used by STD_SECTION.  */

  newsect->id = section_id;
  newsect->index = abfd->section_count;
  newsect->owner = abfd;

  /* Create a symbol whose only job is to point to this section.  This
     is useful for things like relocs which are relative to the base
     of a section.  */
  newsect->symbol = bfd_make_empty_symbol (abfd);
  if (newsect->symbol == NULL)
    return NULL;

  newsect->symbol->name = newsect->name;
  newsect->symbol->value = 0;
  newsect->symbol->section = newsect;
  newsect->symbol->flags = BSF_SECTION_SYM;

  newsect->symbol_ptr_ptr = &newsect->symbol;

  if (! BFD_SEND (abfd, _new_section_hook, (abfd, newsect)))
    return NULL;

  section_id++;
  abfd->section_count++;
  *abfd->section_tail = newsect;
  abfd->section_tail = &newsect->next;
  return newsect;
}

/*
DOCDD
INODE
section prototypes,  , typedef asection, Sections
SUBSECTION
	Section prototypes

These are the functions exported by the section handling part of BFD.
*/

/*
FUNCTION
	bfd_section_list_clear

SYNOPSIS
	void bfd_section_list_clear (bfd *);

DESCRIPTION
	Clears the section list, and also resets the section count and
	hash table entries.
*/

void
bfd_section_list_clear ( bfd *abfd )
{
  abfd->sections = NULL;
  abfd->section_tail = &abfd->sections;
  abfd->section_count = 0;
  memset ((PTR) abfd->section_htab.table, 0,
	  abfd->section_htab.size * sizeof (struct bfd_hash_entry *));
}

/*----------------------------------------------------
 Function name: bfd_get_section_by_name
        Author: Jack Zhao
          Date: 2004-6-1
   Description: 
         Input: 
             bfd *abfd
            const char *name
        Output: asection *bfd_get_section_by_name 
         Notes: This should only be used in special cases; the normal way to process
				all sections of a given name is to use <<bfd_map_over_sections>> and
				<<strcmp>> on the name (or better yet, base it on the section flags
				or something else) for each section.
 Update: 
 Date          Name           Description 
 ============= ============== ======================
 2004-6-1      Jack Zhao      New
----------------------------------------------------*/
asection *bfd_get_section_by_name ( bfd *abfd, const char *name )
{
	struct section_hash_entry *sh;

	sh = section_hash_lookup (&abfd->section_htab, name, false, false);

	if (sh != NULL)
	{
		return &sh->section;
	}

	return NULL;
}

/*
FUNCTION
	bfd_make_section_old_way

SYNOPSIS
	asection *bfd_make_section_old_way(bfd *abfd, const char *name);

DESCRIPTION
	Create a new empty section called @var{name}
	and attach it to the end of the chain of sections for the
	BFD @var{abfd}. An attempt to create a section with a name which
	is already in use returns its pointer without changing the
	section chain.

	It has the funny name since this is the way it used to be
	before it was rewritten....

	Possible errors are:
	o <<bfd_error_invalid_operation>> -
	If output has already started for this BFD.
	o <<bfd_error_no_memory>> -
	If memory allocation fails.

*/

asection *bfd_make_section_old_way ( bfd *abfd, const char *name )
{
  struct section_hash_entry *sh;
  asection *newsect;

  if (abfd->output_has_begun)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return NULL;
    }

  if (strcmp (name, BFD_ABS_SECTION_NAME) == 0)
    return bfd_abs_section_ptr;

  if (strcmp (name, BFD_COM_SECTION_NAME) == 0)
    return bfd_com_section_ptr;

  if (strcmp (name, BFD_UND_SECTION_NAME) == 0)
    return bfd_und_section_ptr;

  if (strcmp (name, BFD_IND_SECTION_NAME) == 0)
    return bfd_ind_section_ptr;

  sh = section_hash_lookup (&abfd->section_htab, name, true, false);
  if (sh == NULL)
    return NULL;

  newsect = &sh->section;
  if (newsect->name != NULL)
    {
      /* Section already exists.  */
      return newsect;
    }

  newsect->name = name;
  return bfd_section_init (abfd, newsect);
}

/*
FUNCTION
	bfd_map_over_sections

SYNOPSIS
	void bfd_map_over_sections(bfd *abfd,
				   void (*func) (bfd *abfd,
						asection *sect,
						PTR obj),
				   PTR obj);

DESCRIPTION
	Call the provided function @var{func} for each section
	attached to the BFD @var{abfd}, passing @var{obj} as an
	argument. The function will be called as if by

|	func(abfd, the_section, obj);

	This is the prefered method for iterating over sections; an
	alternative would be to use a loop:

|	   section *p;
|	   for (p = abfd->sections; p != NULL; p = p->next)
|	      func(abfd, p, ...)

*/

/*VARARGS2*/
void
bfd_map_over_sections (
     bfd *abfd,
     void (*operation) PARAMS ((bfd * abfd, asection * sect, PTR obj)),
     PTR user_storage )
{
  asection *sect;
  unsigned int i = 0;

  for (sect = abfd->sections; sect != NULL; i++, sect = sect->next)
    (*operation) (abfd, sect, user_storage);

  if (i != abfd->section_count)	/* Debugging */
    abort ();
}


#define bfd_get_section_size_now(abfd,sec) \
(sec->reloc_done \
 ? bfd_get_section_size_after_reloc (sec) \
 : bfd_get_section_size_before_reloc (sec))

/*
FUNCTION
	bfd_get_section_contents

SYNOPSIS
	boolean bfd_get_section_contents (bfd *abfd, asection *section,
					  PTR location, file_ptr offset,
					  bfd_size_type count);

DESCRIPTION
	Read data from @var{section} in BFD @var{abfd}
	into memory starting at @var{location}. The data is read at an
	offset of @var{offset} from the start of the input section,
	and is read for @var{count} bytes.

	If the contents of a constructor with the <<SEC_CONSTRUCTOR>>
	flag set are requested or if the section does not have the
	<<SEC_HAS_CONTENTS>> flag set, then the @var{location} is filled
	with zeroes. If no errors occur, <<true>> is returned, else
	<<false>>.

*/
bool
bfd_get_section_contents (
     bfd *abfd,
     sec_ptr section,
     PTR location,
     file_ptr offset,
     bfd_size_type count )
{
  bfd_size_type sz;

  if (section->flags & SEC_CONSTRUCTOR)
    {
      memset (location, 0, (size_t) count);
      return true;
    }

  /* Even if reloc_done is true, this function reads unrelocated
     contents, so we want the raw size.  */
  sz = section->_raw_size;
  if ((bfd_size_type) offset > sz
      || count > sz
      || offset + count > sz
      || count != (size_t) count)
    {
      bfd_set_error (bfd_error_bad_value);
      return false;
    }

  if (count == 0)
    /* Don't bother.  */
    return true;

  if ((section->flags & SEC_HAS_CONTENTS) == 0)
    {
      memset (location, 0, (size_t) count);
      return true;
    }

  if ((section->flags & SEC_IN_MEMORY) != 0)
    {
      memcpy (location, section->contents + offset, (size_t) count);
      return true;
    }

  return BFD_SEND (abfd, _bfd_get_section_contents,
		   (abfd, section, location, offset, count));
}

