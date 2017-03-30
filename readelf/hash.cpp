//#include "stdafx.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "dwarf2.h"
#include "objalloc.h"

/* The default number of entries to use when creating a hash table.  */
#define DEFAULT_SIZE (4051)

extern PTR bfd_malloc (bfd_size_type size);

/* Create a new hash table, given a number of entries.  */
bool bfd_hash_table_init_n (
     struct bfd_hash_table *table,
     struct bfd_hash_entry *(*newfunc) PARAMS ((struct bfd_hash_entry *,
						struct bfd_hash_table *,
						const char *)),
     unsigned int size )
{
  unsigned int alloc;

  alloc = size * sizeof (struct bfd_hash_entry *);

  table->memory = (PTR) objalloc_create ();
  if (table->memory == NULL)
    {
      bfd_set_error (bfd_error_no_memory);
      return false;
    }
  table->table = ((struct bfd_hash_entry **)
		  objalloc_alloc ((struct objalloc *) table->memory, alloc));
  if (table->table == NULL)
    {
      bfd_set_error (bfd_error_no_memory);
      return false;
    }
  memset ((PTR) table->table, 0, alloc);
  table->size = size;
  table->newfunc = newfunc;
  return true;
}

/* Create a new hash table with the default number of entries.  */

bool bfd_hash_table_init (
     struct bfd_hash_table *table,
     struct bfd_hash_entry *(*newfunc) PARAMS ((struct bfd_hash_entry *,
						struct bfd_hash_table *,
						const char *)) )
{
  return bfd_hash_table_init_n (table, newfunc, DEFAULT_SIZE);
}

/* Free a hash table.  */
void bfd_hash_table_free (struct bfd_hash_table *table)
{
  objalloc_free ((struct objalloc *) table->memory);
  table->memory = NULL;
}

/* Look up a string in a hash table.  */
struct bfd_hash_entry *bfd_hash_lookup (
     struct bfd_hash_table *table,
     const char *string,
     bool create,
     bool copy )
{
  register const unsigned char *s;
  register unsigned long hash;
  register unsigned int c;
  struct bfd_hash_entry *hashp;
  unsigned int len;
  unsigned int index;

  hash = 0;
  len = 0;
  s = (const unsigned char *) string;
  while ((c = *s++) != '\0')
    {
      hash += c + (c << 17);
      hash ^= hash >> 2;
    }
  len = (s - (const unsigned char *) string) - 1;
  hash += len + (len << 17);
  hash ^= hash >> 2;

  index = hash % table->size;
  for (hashp = table->table[index];
       hashp != (struct bfd_hash_entry *) NULL;
       hashp = hashp->next)
    {
      if (hashp->hash == hash
	  && strcmp (hashp->string, string) == 0)
	return hashp;
    }

  if (! create)
    return (struct bfd_hash_entry *) NULL;

  hashp = (*table->newfunc) ((struct bfd_hash_entry *) NULL, table, string);
  if (hashp == (struct bfd_hash_entry *) NULL)
    return (struct bfd_hash_entry *) NULL;
  if (copy)
    {
      char *new_obj;

      new_obj = (char *) objalloc_alloc ((struct objalloc *) table->memory,
				     len + 1);
      if (!new_obj)
	{
	  bfd_set_error (bfd_error_no_memory);
	  return (struct bfd_hash_entry *) NULL;
	}
      memcpy (new_obj, string, len + 1);
      string = new_obj;
    }
  hashp->string = string;
  hashp->hash = hash;
  hashp->next = table->table[index];
  table->table[index] = hashp;

  return hashp;
}

/* Replace an entry in a hash table.  */
void bfd_hash_replace (
     struct bfd_hash_table *table,
     struct bfd_hash_entry *old,
     struct bfd_hash_entry *nw )
{
  unsigned int index;
  struct bfd_hash_entry **pph;

  index = old->hash % table->size;
  for (pph = &table->table[index];
       (*pph) != (struct bfd_hash_entry *) NULL;
       pph = &(*pph)->next)
    {
      if (*pph == old)
	{
	  *pph = nw;
	  return;
	}
    }

  abort ();
}

/* Base method for creating a new hash table entry.  */

/*ARGSUSED*/
struct bfd_hash_entry *bfd_hash_newfunc (
     struct bfd_hash_entry *entry,
     struct bfd_hash_table *table,
     const char *string )
{
  if (entry == (struct bfd_hash_entry *) NULL)
    entry = ((struct bfd_hash_entry *)
	     bfd_hash_allocate (table, sizeof (struct bfd_hash_entry)));
  return entry;
}

/* Allocate space in a hash table.  */

PTR
bfd_hash_allocate (
     struct bfd_hash_table *table,
     unsigned int size )
{
  PTR ret;

  ret = objalloc_alloc ((struct objalloc *) table->memory, size);
  if (ret == NULL && size != 0)
    bfd_set_error (bfd_error_no_memory);
  return ret;
}

/* Traverse a hash table.  */

void
bfd_hash_traverse (
     struct bfd_hash_table *table,
     bool (*func) PARAMS ((struct bfd_hash_entry *, PTR)),
     PTR info )
{
  unsigned int i;

  for (i = 0; i < table->size; i++)
    {
      struct bfd_hash_entry *p;

      for (p = table->table[i]; p != NULL; p = p->next)
	{
	  if (! (*func) (p, info))
	    return;
	}
    }
}

/* A few different object file formats (a.out, COFF, ELF) use a string
   table.  These functions support adding strings to a string table,
   returning the byte offset, and writing out the table.

   Possible improvements:
   + look for strings matching trailing substrings of other strings
   + better data structures?  balanced trees?
   + look at reducing memory use elsewhere -- maybe if we didn't have
     to construct the entire symbol table at once, we could get by
     with smaller amounts of VM?  (What effect does that have on the
     string table reductions?)  */

/* An entry in the strtab hash table.  */

struct strtab_hash_entry
{
  struct bfd_hash_entry root;
  /* Index in string table.  */
  bfd_size_type index;
  /* Next string in strtab.  */
  struct strtab_hash_entry *next;
};

/* The strtab hash table.  */

struct bfd_strtab_hash
{
  struct bfd_hash_table table;
  /* Size of strtab--also next available index.  */
  bfd_size_type size;
  /* First string in strtab.  */
  struct strtab_hash_entry *first;
  /* Last string in strtab.  */
  struct strtab_hash_entry *last;
  /* Whether to precede strings with a two byte length, as in the
     XCOFF .debug section.  */
  bool xcoff;
};

static struct bfd_hash_entry *strtab_hash_newfunc
  PARAMS ((struct bfd_hash_entry *, struct bfd_hash_table *, const char *));

/* Routine to create an entry in a strtab.  */

static struct bfd_hash_entry *
strtab_hash_newfunc (
     struct bfd_hash_entry *entry,
     struct bfd_hash_table *table,
     const char *string )
{
  struct strtab_hash_entry *ret = (struct strtab_hash_entry *) entry;

  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (ret == (struct strtab_hash_entry *) NULL)
    ret = ((struct strtab_hash_entry *)
	   bfd_hash_allocate (table, sizeof (struct strtab_hash_entry)));
  if (ret == (struct strtab_hash_entry *) NULL)
    return NULL;

  /* Call the allocation method of the superclass.  */
  ret = ((struct strtab_hash_entry *)
	 bfd_hash_newfunc ((struct bfd_hash_entry *) ret, table, string));

  if (ret)
    {
      /* Initialize the local fields.  */
      ret->index = (bfd_size_type) -1;
      ret->next = NULL;
    }

  return (struct bfd_hash_entry *) ret;
}

/* Look up an entry in an strtab.  */

#define strtab_hash_lookup(t, string, create, copy) \
  ((struct strtab_hash_entry *) \
   bfd_hash_lookup (&(t)->table, (string), (create), (copy)))

/* Create a new strtab.  */

struct bfd_strtab_hash *_bfd_stringtab_init ()
{
  struct bfd_strtab_hash *table;
  bfd_size_type amt = sizeof (struct bfd_strtab_hash);

  table = (struct bfd_strtab_hash *) bfd_malloc (amt);
  if (table == NULL)
    return NULL;

  if (! bfd_hash_table_init (&table->table, strtab_hash_newfunc))
    {
      free (table);
      return NULL;
    }

  table->size = 0;
  table->first = NULL;
  table->last = NULL;
  table->xcoff = false;

  return table;
}

/* Create a new strtab in which the strings are output in the format
   used in the XCOFF .debug section: a two byte length precedes each
   string.  */

struct bfd_strtab_hash *_bfd_xcoff_stringtab_init ()
{
  struct bfd_strtab_hash *ret;

  ret = _bfd_stringtab_init ();
  if (ret != NULL)
    ret->xcoff = true;
  return ret;
}

/* Free a strtab.  */

void
_bfd_stringtab_free ( struct bfd_strtab_hash *table )
{
  bfd_hash_table_free (&table->table);
  free (table);
}

/* Get the index of a string in a strtab, adding it if it is not
   already present.  If HASH is false, we don't really use the hash
   table, and we don't eliminate duplicate strings.  */

bfd_size_type
_bfd_stringtab_add (
     struct bfd_strtab_hash *tab,
     const char *str,
     bool hash,
     bool copy )
{
  register struct strtab_hash_entry *entry;

  if (hash)
    {
      entry = strtab_hash_lookup (tab, str, true, copy);
      if (entry == NULL)
	return (bfd_size_type) -1;
    }
  else
    {
      entry = ((struct strtab_hash_entry *)
	       bfd_hash_allocate (&tab->table,
				  sizeof (struct strtab_hash_entry)));
      if (entry == NULL)
	return (bfd_size_type) -1;
      if (! copy)
	entry->root.string = str;
      else
	{
	  char *n;

	  n = (char *) bfd_hash_allocate (&tab->table, strlen (str) + 1);
	  if (n == NULL)
	    return (bfd_size_type) -1;
	  entry->root.string = n;
	}
      entry->index = (bfd_size_type) -1;
      entry->next = NULL;
    }

  if (entry->index == (bfd_size_type) -1)
    {
      entry->index = tab->size;
      tab->size += strlen (str) + 1;
      if (tab->xcoff)
	{
	  entry->index += 2;
	  tab->size += 2;
	}
      if (tab->first == NULL)
	tab->first = entry;
      else
	tab->last->next = entry;
      tab->last = entry;
    }

  return entry->index;
}

/* Get the number of bytes in a strtab.  */

bfd_size_type
_bfd_stringtab_size (
     struct bfd_strtab_hash *tab )
{
  return tab->size;
}

/* Write out a strtab.  ABFD must already be at the right location in
   the file.  */

bool
_bfd_stringtab_emit (
     register bfd *abfd,
     struct bfd_strtab_hash *tab )
{
  register bool xcoff;
  register struct strtab_hash_entry *entry;

  xcoff = tab->xcoff;

  for (entry = tab->first; entry != NULL; entry = entry->next)
    {
      const char *str;
      size_t len;

      str = entry->root.string;
      len = strlen (str) + 1;

      if (xcoff)
	{
	  bfd_byte buf[2];

	  /* The output length includes the null byte.  */
	  bfd_put_16 (abfd, (bfd_vma) len, buf);
/* --- Removed by Jack Zhao on 2004-6-1---
	  if (bfd_bwrite ((PTR) buf, (bfd_size_type) 2, abfd) != 2)
	    return false;
---------------------------------------*/
	}

/* --- Removed by Jack Zhao on 2004-6-1---
      if (bfd_bwrite ((PTR) str, (bfd_size_type) len, abfd) != len)
	return false;
---------------------------------------*/
    }

  return true;
}
