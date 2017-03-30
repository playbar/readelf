/*------------------------------------------------------------------------------
 dwarf2.cpp
------------------------------------------------------------------------------
 Copyright 2004 by Inventec Besta Co., Ltd. All rights reserved.
 Compiler:     Visual C++ 6.0, SP3
 Author:       Jack Zhao
 Date:         2004-5-28
 Description:  
 Side Effects:
 Functions:
 Notes:    
 Update: 2004-5-28 10:56:35
 Date          Name           Description 
 ============= ============== ======================
 2004-5-28     Jack Zhao      New
------------------------------------------------------------------------------*/
//#include "stdafx.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"
#include "dwarf2.h"
#include <assert.h>

void _bfd_default_error_handler VPARAMS ((const char *s, ...));
const char *_bfd_error_program_name;

unsigned int read_1_byte PARAMS ((bfd *, char *));
int read_1_signed_byte PARAMS ((bfd *, char *));
unsigned int read_2_bytes PARAMS ((bfd *, char *));
unsigned int read_4_bytes PARAMS ((bfd *, char *));
bfd_vma read_8_bytes PARAMS ((bfd *, char *));
char *read_n_bytes PARAMS ((bfd *, char *, unsigned int));
char *read_string PARAMS ((bfd *, char *, unsigned int *));
char *read_indirect_string PARAMS ((struct comp_unit *, char *, unsigned int *));
unsigned int read_unsigned_leb128  PARAMS ((bfd *, char *, unsigned int *));
int read_signed_leb128  PARAMS ((bfd *, char *, unsigned int *));
bfd_vma read_address PARAMS ((struct comp_unit *, char *));
struct abbrev_info *lookup_abbrev  PARAMS ((unsigned int, struct abbrev_info **));
struct abbrev_info **read_abbrevs  PARAMS ((bfd *, bfd_vma, struct dwarf2_debug *));
char *read_attribute  PARAMS ((struct attribute *, struct attr_abbrev *, struct comp_unit *, char *));
char *read_attribute_value PARAMS ((struct attribute *, unsigned, struct comp_unit *, char *));
void add_line_info PARAMS ((struct line_info_table *, bfd_vma, char *, unsigned int, unsigned int, int));
char *concat_filename PARAMS ((struct line_info_table *, unsigned int));
void arange_add PARAMS ((struct comp_unit *, bfd_vma, bfd_vma));
struct line_info_table *decode_line_info  PARAMS ((struct comp_unit *, struct dwarf2_debug *));
bool lookup_address_in_line_info_table  PARAMS ((struct line_info_table *, bfd_vma, struct funcinfo *, const char **, unsigned int *));
bool lookup_address_in_function_table  PARAMS ((struct funcinfo *, bfd_vma, struct funcinfo **, const char **));
bool scan_unit_for_functions PARAMS ((struct comp_unit *));
bfd_vma find_rela_addend  PARAMS ((bfd *, asection *, bfd_size_type, asymbol**));
struct comp_unit *parse_comp_unit  PARAMS ((bfd *, struct dwarf2_debug *, bfd_vma, unsigned int));
bool comp_unit_contains_address  PARAMS ((struct comp_unit *, bfd_vma));
bool comp_unit_find_nearest_line  PARAMS ((struct comp_unit *, bfd_vma, const char **, const char **, unsigned int *, struct dwarf2_debug *));
asection *find_debug_info PARAMS ((bfd *, asection *));

PTR bfd_alloc (bfd *abfd, bfd_size_type size);
PTR bfd_zalloc (bfd *abfd, bfd_size_type size);
PTR bfd_realloc (struct attr_abbrev *abbr, bfd_size_type size);
PTR bfd_malloc (bfd_size_type size);

bfd_error_handler_type _bfd_error_handler = _bfd_default_error_handler;

/* Convert a DIE tag into its string name.  */
const char *dwarf_tag_name (unsigned tag)
{
  switch (tag)
    {
    case DW_TAG_padding:
      return "DW_TAG_padding";
    case DW_TAG_array_type:
      return "DW_TAG_array_type";
    case DW_TAG_class_type:
      return "DW_TAG_class_type";
    case DW_TAG_entry_point:
      return "DW_TAG_entry_point";
    case DW_TAG_enumeration_type:
      return "DW_TAG_enumeration_type";
    case DW_TAG_formal_parameter:
      return "DW_TAG_formal_parameter";
    case DW_TAG_imported_declaration:
      return "DW_TAG_imported_declaration";
    case DW_TAG_label:
      return "DW_TAG_label";
    case DW_TAG_lexical_block:
      return "DW_TAG_lexical_block";
    case DW_TAG_member:
      return "DW_TAG_member";
    case DW_TAG_pointer_type:
      return "DW_TAG_pointer_type";
    case DW_TAG_reference_type:
      return "DW_TAG_reference_type";
    case DW_TAG_compile_unit:
      return "DW_TAG_compile_unit";
    case DW_TAG_string_type:
      return "DW_TAG_string_type";
    case DW_TAG_structure_type:
      return "DW_TAG_structure_type";
    case DW_TAG_subroutine_type:
      return "DW_TAG_subroutine_type";
    case DW_TAG_typedef:
      return "DW_TAG_typedef";
    case DW_TAG_union_type:
      return "DW_TAG_union_type";
    case DW_TAG_unspecified_parameters:
      return "DW_TAG_unspecified_parameters";
    case DW_TAG_variant:
      return "DW_TAG_variant";
    case DW_TAG_common_block:
      return "DW_TAG_common_block";
    case DW_TAG_common_inclusion:
      return "DW_TAG_common_inclusion";
    case DW_TAG_inheritance:
      return "DW_TAG_inheritance";
    case DW_TAG_inlined_subroutine:
      return "DW_TAG_inlined_subroutine";
    case DW_TAG_module:
      return "DW_TAG_module";
    case DW_TAG_ptr_to_member_type:
      return "DW_TAG_ptr_to_member_type";
    case DW_TAG_set_type:
      return "DW_TAG_set_type";
    case DW_TAG_subrange_type:
      return "DW_TAG_subrange_type";
    case DW_TAG_with_stmt:
      return "DW_TAG_with_stmt";
    case DW_TAG_access_declaration:
      return "DW_TAG_access_declaration";
    case DW_TAG_base_type:
      return "DW_TAG_base_type";
    case DW_TAG_catch_block:
      return "DW_TAG_catch_block";
    case DW_TAG_const_type:
      return "DW_TAG_const_type";
    case DW_TAG_constant:
      return "DW_TAG_constant";
    case DW_TAG_enumerator:
      return "DW_TAG_enumerator";
    case DW_TAG_file_type:
      return "DW_TAG_file_type";
    case DW_TAG_friend:
      return "DW_TAG_friend";
    case DW_TAG_namelist:
      return "DW_TAG_namelist";
    case DW_TAG_namelist_item:
      return "DW_TAG_namelist_item";
    case DW_TAG_packed_type:
      return "DW_TAG_packed_type";
    case DW_TAG_subprogram:
      return "DW_TAG_subprogram";
    case DW_TAG_template_type_param:
      return "DW_TAG_template_type_param";
    case DW_TAG_template_value_param:
      return "DW_TAG_template_value_param";
    case DW_TAG_thrown_type:
      return "DW_TAG_thrown_type";
    case DW_TAG_try_block:
      return "DW_TAG_try_block";
    case DW_TAG_variant_part:
      return "DW_TAG_variant_part";
    case DW_TAG_variable:
      return "DW_TAG_variable";
    case DW_TAG_volatile_type:
      return "DW_TAG_volatile_type";
    case DW_TAG_MIPS_loop:
      return "DW_TAG_MIPS_loop";
    case DW_TAG_format_label:
      return "DW_TAG_format_label";
    case DW_TAG_function_template:
      return "DW_TAG_function_template";
    case DW_TAG_class_template:
      return "DW_TAG_class_template";
    case DW_TAG_GNU_BINCL:
      return "DW_TAG_GNU_BINCL";
    case DW_TAG_GNU_EINCL:
      return "DW_TAG_GNU_EINCL";
    default:
      return "DW_TAG_<unknown>";
    }
}

/* Convert a DWARF attribute code into its string name.  */
const char *dwarf_attr_name (unsigned attr)
{
  switch (attr)
    {
    case DW_AT_sibling:
      return "DW_AT_sibling";
    case DW_AT_location:
      return "DW_AT_location";
    case DW_AT_name:
      return "DW_AT_name";
    case DW_AT_ordering:
      return "DW_AT_ordering";
    case DW_AT_subscr_data:
      return "DW_AT_subscr_data";
    case DW_AT_byte_size:
      return "DW_AT_byte_size";
    case DW_AT_bit_offset:
      return "DW_AT_bit_offset";
    case DW_AT_bit_size:
      return "DW_AT_bit_size";
    case DW_AT_element_list:
      return "DW_AT_element_list";
    case DW_AT_stmt_list:
      return "DW_AT_stmt_list";
    case DW_AT_low_pc:
      return "DW_AT_low_pc";
    case DW_AT_high_pc:
      return "DW_AT_high_pc";
    case DW_AT_language:
      return "DW_AT_language";
    case DW_AT_member:
      return "DW_AT_member";
    case DW_AT_discr:
      return "DW_AT_discr";
    case DW_AT_discr_value:
      return "DW_AT_discr_value";
    case DW_AT_visibility:
      return "DW_AT_visibility";
    case DW_AT_import:
      return "DW_AT_import";
    case DW_AT_string_length:
      return "DW_AT_string_length";
    case DW_AT_common_reference:
      return "DW_AT_common_reference";
    case DW_AT_comp_dir:
      return "DW_AT_comp_dir";
    case DW_AT_const_value:
      return "DW_AT_const_value";
    case DW_AT_containing_type:
      return "DW_AT_containing_type";
    case DW_AT_default_value:
      return "DW_AT_default_value";
    case DW_AT_inline:
      return "DW_AT_inline";
    case DW_AT_is_optional:
      return "DW_AT_is_optional";
    case DW_AT_lower_bound:
      return "DW_AT_lower_bound";
    case DW_AT_producer:
      return "DW_AT_producer";
    case DW_AT_prototyped:
      return "DW_AT_prototyped";
    case DW_AT_return_addr:
      return "DW_AT_return_addr";
    case DW_AT_start_scope:
      return "DW_AT_start_scope";
    case DW_AT_stride_size:
      return "DW_AT_stride_size";
    case DW_AT_upper_bound:
      return "DW_AT_upper_bound";
    case DW_AT_abstract_origin:
      return "DW_AT_abstract_origin";
    case DW_AT_accessibility:
      return "DW_AT_accessibility";
    case DW_AT_address_class:
      return "DW_AT_address_class";
    case DW_AT_artificial:
      return "DW_AT_artificial";
    case DW_AT_base_types:
      return "DW_AT_base_types";
    case DW_AT_calling_convention:
      return "DW_AT_calling_convention";
    case DW_AT_count:
      return "DW_AT_count";
    case DW_AT_data_member_location:
      return "DW_AT_data_member_location";
    case DW_AT_decl_column:
      return "DW_AT_decl_column";
    case DW_AT_decl_file:
      return "DW_AT_decl_file";
    case DW_AT_decl_line:
      return "DW_AT_decl_line";
    case DW_AT_declaration:
      return "DW_AT_declaration";
    case DW_AT_discr_list:
      return "DW_AT_discr_list";
    case DW_AT_encoding:
      return "DW_AT_encoding";
    case DW_AT_external:
      return "DW_AT_external";
    case DW_AT_frame_base:
      return "DW_AT_frame_base";
    case DW_AT_friend:
      return "DW_AT_friend";
    case DW_AT_identifier_case:
      return "DW_AT_identifier_case";
    case DW_AT_macro_info:
      return "DW_AT_macro_info";
    case DW_AT_namelist_items:
      return "DW_AT_namelist_items";
    case DW_AT_priority:
      return "DW_AT_priority";
    case DW_AT_segment:
      return "DW_AT_segment";
    case DW_AT_specification:
      return "DW_AT_specification";
    case DW_AT_static_link:
      return "DW_AT_static_link";
    case DW_AT_type:
      return "DW_AT_type";
    case DW_AT_use_location:
      return "DW_AT_use_location";
    case DW_AT_variable_parameter:
      return "DW_AT_variable_parameter";
    case DW_AT_virtuality:
      return "DW_AT_virtuality";
    case DW_AT_vtable_elem_location:
      return "DW_AT_vtable_elem_location";

    case DW_AT_allocated:
      return "DW_AT_allocated";
    case DW_AT_associated:
      return "DW_AT_associated";
    case DW_AT_data_location:
      return "DW_AT_data_location";
    case DW_AT_stride:
      return "DW_AT_stride";
    case DW_AT_entry_pc:
      return "DW_AT_entry_pc";
    case DW_AT_use_UTF8:
      return "DW_AT_use_UTF8";
    case DW_AT_extension:
      return "DW_AT_extension";
    case DW_AT_ranges:
      return "DW_AT_ranges";
    case DW_AT_trampoline:
      return "DW_AT_trampoline";
    case DW_AT_call_column:
      return "DW_AT_call_column";
    case DW_AT_call_file:
      return "DW_AT_call_file";
    case DW_AT_call_line:
      return "DW_AT_call_line";

    case DW_AT_MIPS_fde:
      return "DW_AT_MIPS_fde";
    case DW_AT_MIPS_loop_begin:
      return "DW_AT_MIPS_loop_begin";
    case DW_AT_MIPS_tail_loop_begin:
      return "DW_AT_MIPS_tail_loop_begin";
    case DW_AT_MIPS_epilog_begin:
      return "DW_AT_MIPS_epilog_begin";
    case DW_AT_MIPS_loop_unroll_factor:
      return "DW_AT_MIPS_loop_unroll_factor";
    case DW_AT_MIPS_software_pipeline_depth:
      return "DW_AT_MIPS_software_pipeline_depth";
    case DW_AT_MIPS_linkage_name:
      return "DW_AT_MIPS_linkage_name";
    case DW_AT_MIPS_stride:
      return "DW_AT_MIPS_stride";
    case DW_AT_MIPS_abstract_name:
      return "DW_AT_MIPS_abstract_name";
    case DW_AT_MIPS_clone_origin:
      return "DW_AT_MIPS_clone_origin";
    case DW_AT_MIPS_has_inlines:
      return "DW_AT_MIPS_has_inlines";

    case DW_AT_sf_names:
      return "DW_AT_sf_names";
    case DW_AT_src_info:
      return "DW_AT_src_info";
    case DW_AT_mac_info:
      return "DW_AT_mac_info";
    case DW_AT_src_coords:
      return "DW_AT_src_coords";
    case DW_AT_body_begin:
      return "DW_AT_body_begin";
    case DW_AT_body_end:
      return "DW_AT_body_end";
    case DW_AT_GNU_vector:
      return "DW_AT_GNU_vector";

    case DW_AT_VMS_rtnbeg_pd_address:
      return "DW_AT_VMS_rtnbeg_pd_address";

    default:
      return "DW_AT_<unknown>";
    }
}

/* Convert a DWARF value form code into its string name.  */
const char *dwarf_form_name (unsigned form)
{
  switch (form)
    {
    case DW_FORM_addr:
      return "DW_FORM_addr";
    case DW_FORM_block2:
      return "DW_FORM_block2";
    case DW_FORM_block4:
      return "DW_FORM_block4";
    case DW_FORM_data2:
      return "DW_FORM_data2";
    case DW_FORM_data4:
      return "DW_FORM_data4";
    case DW_FORM_data8:
      return "DW_FORM_data8";
    case DW_FORM_string:
      return "DW_FORM_string";
    case DW_FORM_block:
      return "DW_FORM_block";
    case DW_FORM_block1:
      return "DW_FORM_block1";
    case DW_FORM_data1:
      return "DW_FORM_data1";
    case DW_FORM_flag:
      return "DW_FORM_flag";
    case DW_FORM_sdata:
      return "DW_FORM_sdata";
    case DW_FORM_strp:
      return "DW_FORM_strp";
    case DW_FORM_udata:
      return "DW_FORM_udata";
    case DW_FORM_ref_addr:
      return "DW_FORM_ref_addr";
    case DW_FORM_ref1:
      return "DW_FORM_ref1";
    case DW_FORM_ref2:
      return "DW_FORM_ref2";
    case DW_FORM_ref4:
      return "DW_FORM_ref4";
    case DW_FORM_ref8:
      return "DW_FORM_ref8";
    case DW_FORM_ref_udata:
      return "DW_FORM_ref_udata";
    case DW_FORM_indirect:
      return "DW_FORM_indirect";
    default:
      return "DW_FORM_<unknown>";
    }
}

/* VERBATIM
   The following function up to the END VERBATIM mark are
   copied directly from dwarf2read.c.  */

/* Read dwarf information from a buffer.  */

unsigned int read_1_byte (bfd *abfd, char *buf)
{
  return bfd_get_8 (abfd, (bfd_byte *) buf);
}

int read_1_signed_byte (bfd *abfd, char *buf)
{
  return bfd_get_signed_8 (abfd, (bfd_byte *) buf);
}

unsigned int read_2_bytes (bfd *abfd, char *buf)
{
  return bfd_get_16 (abfd, (bfd_byte *) buf);
}

unsigned int read_4_bytes (bfd *abfd, char *buf)
{
  return bfd_get_32 (abfd, (bfd_byte *) buf);
}

bfd_vma read_8_bytes (bfd *abfd, char *buf)
{
  return bfd_get_64 (abfd, (bfd_byte *) buf);
}

char *read_n_bytes (bfd *abfd, char *buf, unsigned int size)
{
  /* If the size of a host char is 8 bits, we can return a pointer
     to the buffer, otherwise we have to copy the data to a buffer
     allocated on the temporary obstack.  */
  return buf;
}

char *read_string (bfd *abfd, char *buf, unsigned int *bytes_read_ptr)
{
  /* Return a pointer to the embedded string.  */
  if (*buf == '\0')
    {
      *bytes_read_ptr = 1;
      return NULL;
    }

  *bytes_read_ptr = strlen (buf) + 1;
  return buf;
}

char *read_indirect_string (struct comp_unit* unit, char *buf, unsigned int *bytes_read_ptr)
{
  bfd_vma offset;
  struct dwarf2_debug *stash = unit->stash;

  if (unit->offset_size == 4)
    offset = read_4_bytes (unit->abfd, buf);
  else
    offset = read_8_bytes (unit->abfd, buf);
  *bytes_read_ptr = unit->offset_size;

  if (! stash->dwarf_str_buffer)
    {
      asection *msec;
      bfd *abfd = unit->abfd;

      msec = bfd_get_section_by_name (abfd, ".debug_str");
      if (! msec)
	{
	  (*_bfd_error_handler)
	    ("Dwarf Error: Can't find .debug_str section.");
	  bfd_set_error (bfd_error_bad_value);
	  return NULL;
	}

      stash->dwarf_str_size = msec->_raw_size;
      stash->dwarf_str_buffer = (char*) bfd_alloc (abfd, msec->_raw_size);
      if (! stash->dwarf_abbrev_buffer)
	return NULL;

      if (! bfd_get_section_contents (abfd, msec, stash->dwarf_str_buffer,
				      (bfd_vma) 0, msec->_raw_size))
	return NULL;
    }

  if (offset >= stash->dwarf_str_size)
    {
      (*_bfd_error_handler) (("Dwarf Error: DW_FORM_strp offset (%lu) greater than or equal to .debug_str size (%lu)."),
			     (unsigned long) offset, stash->dwarf_str_size);
      bfd_set_error (bfd_error_bad_value);
      return NULL;
    }

  buf = stash->dwarf_str_buffer + offset;  
  if (*buf == '\0')
    return NULL;
  return buf;
}

unsigned int read_unsigned_leb128 (bfd *abfd, char *buf, unsigned int *bytes_read_ptr)
{
  unsigned int  result;
  unsigned int  num_read;
  int           shift;
  unsigned char byte;

  result   = 0;
  shift    = 0;
  num_read = 0;

  do
    {
      byte = bfd_get_8 (abfd, (bfd_byte *) buf);
      buf ++;
      num_read ++;
      result |= ((byte & 0x7f) << shift);
      shift += 7;
    }
  while (byte & 0x80);

  * bytes_read_ptr = num_read;

  return result;
}

int read_signed_leb128 (bfd *abfd, char *buf, unsigned int *bytes_read_ptr)
{
  int           result;
  int           shift;
  int           num_read;
  unsigned char byte;

  result = 0;
  shift = 0;
  num_read = 0;

  do
    {
      byte = bfd_get_8 (abfd, (bfd_byte *) buf);
      buf ++;
      num_read ++;
      result |= ((byte & 0x7f) << shift);
      shift += 7;
    }
  while (byte & 0x80);

  if ((shift < 32) && (byte & 0x40))
    result |= -(1 << shift);

  * bytes_read_ptr = num_read;

  return result;
}

/* END VERBATIM */
bfd_vma read_address (struct comp_unit* unit, char *buf)
{
  switch (unit->addr_size)
    {
    case 8:
      return bfd_get_64 (unit->abfd, (bfd_byte *) buf);
    case 4:
      return bfd_get_32 (unit->abfd, (bfd_byte *) buf);
    case 2:
      return bfd_get_16 (unit->abfd, (bfd_byte *) buf);
    default:
      abort ();
    }
}

/* Lookup an abbrev_info structure in the abbrev hash table.  */
struct abbrev_info *lookup_abbrev (unsigned int number, struct abbrev_info **abbrevs)
{
	unsigned int hash_number;
	struct abbrev_info *abbrev;

	hash_number = number % ABBREV_HASH_SIZE;
	abbrev = abbrevs[hash_number];

	while (abbrev)
	{
		if (abbrev->number == number)
		{
			return abbrev;
		}
		else
		{
			abbrev = abbrev->next;
		}
	}

	return NULL;
}

/* In DWARF version 2, the description of the debugging information is
   stored in a separate .debug_abbrev section.  Before we read any
   dies from a section we read in all abbreviations and install them
   in a hash table.  */
struct abbrev_info** read_abbrevs (bfd * abfd, bfd_vma offset, struct dwarf2_debug *stash)
{
	struct abbrev_info **abbrevs;
	char *abbrev_ptr;
	struct abbrev_info *cur_abbrev;
	unsigned int abbrev_number, bytes_read, abbrev_name;
	unsigned int abbrev_form, hash_number;
	bfd_size_type amt;

	if( !stash->dwarf_abbrev_buffer )
    {
		asection *msec;
		msec = bfd_get_section_by_name(abfd, ".debug_abbrev");
		if( !msec )
		{
			(*_bfd_error_handler) (("Dwarf Error: Can't find .debug_abbrev section."));
			bfd_set_error (bfd_error_bad_value);
			return 0;
		}

		stash->dwarf_abbrev_size = msec->_raw_size;
		stash->dwarf_abbrev_buffer = (char*)bfd_alloc (abfd, msec->_raw_size);
		if( !stash->dwarf_abbrev_buffer )
		{
			return 0;
		}

		if (! bfd_get_section_contents (abfd, msec, stash->dwarf_abbrev_buffer, (bfd_vma) 0, msec->_raw_size))
		{
			return 0;
		}
    }

	if (offset >= stash->dwarf_abbrev_size)
	{
		(*_bfd_error_handler) (("Dwarf Error: Abbrev offset (%lu) greater than or equal to .debug_abbrev size (%lu)."),	(unsigned long) offset, stash->dwarf_abbrev_size);
		bfd_set_error (bfd_error_bad_value);
		return 0;
	}

	amt = sizeof(struct abbrev_info*) * ABBREV_HASH_SIZE;
	abbrevs = (struct abbrev_info**) bfd_zalloc (abfd, amt);

	abbrev_ptr = stash->dwarf_abbrev_buffer + offset;
	abbrev_number = read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
	abbrev_ptr += bytes_read;

	/* Loop until we reach an abbrev number of 0.  */
	while (abbrev_number)
	{
		amt = sizeof (struct abbrev_info);
		cur_abbrev = (struct abbrev_info *) bfd_zalloc (abfd, amt);

		/* Read in abbrev header.  */
		cur_abbrev->number = abbrev_number;
		cur_abbrev->tag = (enum dwarf_tag)read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
		abbrev_ptr += bytes_read;
		cur_abbrev->has_children = read_1_byte (abfd, abbrev_ptr);
		abbrev_ptr += 1;

		/* Now read in declarations.  */
		abbrev_name = read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
		abbrev_ptr += bytes_read;
		abbrev_form = read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
		abbrev_ptr += bytes_read;

		while (abbrev_name)
		{
			if ((cur_abbrev->num_attrs % ATTR_ALLOC_CHUNK) == 0)
			{
				amt = cur_abbrev->num_attrs + ATTR_ALLOC_CHUNK;
				amt *= sizeof (struct attr_abbrev);
				cur_abbrev->attrs = ((struct attr_abbrev *)
				bfd_realloc (cur_abbrev->attrs, amt));
				if (! cur_abbrev->attrs)
				{
					return 0;
				}
			}

			cur_abbrev->attrs[cur_abbrev->num_attrs].name = (enum dwarf_attribute)abbrev_name;
			cur_abbrev->attrs[cur_abbrev->num_attrs++].form = (enum dwarf_form)abbrev_form;
			abbrev_name = read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
			abbrev_ptr += bytes_read;
			abbrev_form = read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
			abbrev_ptr += bytes_read;
		}

		hash_number = abbrev_number % ABBREV_HASH_SIZE;
		cur_abbrev->next = abbrevs[hash_number];
		abbrevs[hash_number] = cur_abbrev;

		/* Get next abbreviation.
		 Under Irix6 the abbreviations for a compilation unit are not
		 always properly terminated with an abbrev number of 0.
		 Exit loop if we encounter an abbreviation which we have
		 already read (which means we are about to read the abbreviations
		 for the next compile unit) or if the end of the abbreviation
		 table is reached.  */
		if( (unsigned int)(abbrev_ptr - stash->dwarf_abbrev_buffer) >= stash->dwarf_abbrev_size)
		{
			break;
		}

		abbrev_number = read_unsigned_leb128 (abfd, abbrev_ptr, &bytes_read);
		abbrev_ptr += bytes_read;
		if( lookup_abbrev(abbrev_number,abbrevs) != NULL )
		{
			break;
		}
    }

	return abbrevs;
}

/* Read an attribute value described by an attribute form.  */
char *read_attribute_value (struct attribute *attr, unsigned form, struct comp_unit *unit, char* info_ptr)
{
	bfd *abfd = unit->abfd;
	unsigned int bytes_read;
	struct dwarf_block *blk;
	bfd_size_type amt;

	attr->form = (enum dwarf_form)form;

	switch (form)
	{
		case DW_FORM_addr:
		  /* FIXME: DWARF3 draft sais DW_FORM_ref_addr is offset_size.  */
		case DW_FORM_ref_addr:
		  DW_ADDR (attr) = read_address (unit, info_ptr);
		  info_ptr += unit->addr_size;
		  break;
		case DW_FORM_block2:
		  amt = sizeof (struct dwarf_block);
		  blk = (struct dwarf_block *) bfd_alloc (abfd, amt);
		  blk->size = read_2_bytes (abfd, info_ptr);
		  info_ptr += 2;
		  blk->data = read_n_bytes (abfd, info_ptr, blk->size);
		  info_ptr += blk->size;
		  DW_BLOCK (attr) = blk;
		  break;
		case DW_FORM_block4:
		  amt = sizeof (struct dwarf_block);
		  blk = (struct dwarf_block *) bfd_alloc (abfd, amt);
		  blk->size = read_4_bytes (abfd, info_ptr);
		  info_ptr += 4;
		  blk->data = read_n_bytes (abfd, info_ptr, blk->size);
		  info_ptr += blk->size;
		  DW_BLOCK (attr) = blk;
		  break;
		case DW_FORM_data2:
		  DW_UNSND (attr) = read_2_bytes (abfd, info_ptr);
		  info_ptr += 2;
		  break;
		case DW_FORM_data4:
		  DW_UNSND (attr) = read_4_bytes (abfd, info_ptr);
		  info_ptr += 4;
		  break;
		case DW_FORM_data8:
		  DW_UNSND (attr) = read_8_bytes (abfd, info_ptr);
		  info_ptr += 8;
		  break;
		case DW_FORM_string:
		  DW_STRING (attr) = read_string (abfd, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  break;
		case DW_FORM_strp:
		  DW_STRING (attr) = read_indirect_string (unit, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  break;
		case DW_FORM_block:
		  amt = sizeof (struct dwarf_block);
		  blk = (struct dwarf_block *) bfd_alloc (abfd, amt);
		  blk->size = read_unsigned_leb128 (abfd, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  blk->data = read_n_bytes (abfd, info_ptr, blk->size);
		  info_ptr += blk->size;
		  DW_BLOCK (attr) = blk;
		  break;
		case DW_FORM_block1:
		  amt = sizeof (struct dwarf_block);
		  blk = (struct dwarf_block *) bfd_alloc (abfd, amt);
		  blk->size = read_1_byte (abfd, info_ptr);
		  info_ptr += 1;
		  blk->data = read_n_bytes (abfd, info_ptr, blk->size);
		  info_ptr += blk->size;
		  DW_BLOCK (attr) = blk;
		  break;
		case DW_FORM_data1:
		  DW_UNSND (attr) = read_1_byte (abfd, info_ptr);
		  info_ptr += 1;
		  break;
		case DW_FORM_flag:
		  DW_UNSND (attr) = read_1_byte (abfd, info_ptr);
		  info_ptr += 1;
		  break;
		case DW_FORM_sdata:
		  DW_SND (attr) = read_signed_leb128 (abfd, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  break;
		case DW_FORM_udata:
		  DW_UNSND (attr) = read_unsigned_leb128 (abfd, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  break;
		case DW_FORM_ref1:
		  DW_UNSND (attr) = read_1_byte (abfd, info_ptr);
		  info_ptr += 1;
		  break;
		case DW_FORM_ref2:
		  DW_UNSND (attr) = read_2_bytes (abfd, info_ptr);
		  info_ptr += 2;
		  break;
		case DW_FORM_ref4:
		  DW_UNSND (attr) = read_4_bytes (abfd, info_ptr);
		  info_ptr += 4;
		  break;
		case DW_FORM_ref8:
		  DW_UNSND (attr) = read_8_bytes (abfd, info_ptr);
		  info_ptr += 8;
		  break;
		case DW_FORM_ref_udata:
		  DW_UNSND (attr) = read_unsigned_leb128 (abfd, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  break;
		case DW_FORM_indirect:
		  form = read_unsigned_leb128 (abfd, info_ptr, &bytes_read);
		  info_ptr += bytes_read;
		  info_ptr = read_attribute_value (attr, form, unit, info_ptr);
		  break;
		default:
		  (*_bfd_error_handler) (("Dwarf Error: Invalid or unhandled FORM value: %u."),
					 form);
		  bfd_set_error (bfd_error_bad_value);
	}

	return info_ptr;
}

/* Read an attribute described by an abbreviated attribute.  */
char *read_attribute (struct attribute *attr, struct attr_abbrev *abbrev, struct comp_unit *unit, char *info_ptr)
{
	attr->name = abbrev->name;
	info_ptr = read_attribute_value (attr, abbrev->form, unit, info_ptr);
	return info_ptr;
}

/* Source line information table routines.  */
#define FILE_ALLOC_CHUNK 5
#define DIR_ALLOC_CHUNK 5

struct line_info
{
  struct line_info* prev_line;
  bfd_vma address;
  char* filename;
  unsigned int line;
  unsigned int column;
  int end_sequence;		/* End of (sequential) code sequence.  */
};

struct fileinfo
{
  char *name;
  unsigned int dir;
  unsigned int time;
  unsigned int size;
};

struct line_info_table
{
  bfd* abfd;
  unsigned int num_files;
  unsigned int num_dirs;
  char* comp_dir;
  char** dirs;
  struct fileinfo* files;
  struct line_info* last_line;
};

struct funcinfo
{
  struct funcinfo *prev_func;
  char* name;
  bfd_vma low;
  bfd_vma high;
};

void add_line_info (
     struct line_info_table* table,
     bfd_vma address,
     char* filename,
     unsigned int line,
     unsigned int column,
     int end_sequence )
{
  bfd_size_type amt = sizeof (struct line_info);
  struct line_info* info = (struct line_info*) bfd_alloc (table->abfd, amt);

  info->prev_line = table->last_line;
  table->last_line = info;

  info->address = address;
  info->filename = filename;
  info->line = line;
  info->column = column;
  info->end_sequence = end_sequence;
}

char *concat_filename ( struct line_info_table* table, unsigned int file )
{
  char* filename;

  if (file - 1 >= table->num_files)
    {
      (*_bfd_error_handler)
	(("Dwarf Error: mangled line number section (bad file number)."));
      return "<unknown>";
    }

  filename = table->files[file - 1].name;
  if (IS_ABSOLUTE_PATH(filename))
    return filename;
  else
    {
      char* dirname = (table->files[file - 1].dir
		       ? table->dirs[table->files[file - 1].dir - 1]
		       : table->comp_dir);

      /* Not all tools set DW_AT_comp_dir, so dirname may be unknown.  The
	 best we can do is return the filename part.  */
/* --- Replaced by Jack Zhao on 2004-5-31---
      if (dirname == NULL)
	return filename;
      else
	return (char*) concat (dirname, "/", filename, NULL);
*/
/* The new is: */
	return filename;
/*----------------------------------------------------*/
    }
}

void arange_add( struct comp_unit *unit, bfd_vma low_pc, bfd_vma high_pc )
{
  struct arange *arange;

  /* First see if we can cheaply extend an existing range.  */
  arange = &unit->arange;

  do
    {
      if (low_pc == arange->high)
	{
	  arange->high = high_pc;
	  return;
	}
      if (high_pc == arange->low)
	{
	  arange->low = low_pc;
	  return;
	}
      arange = arange->next;
    }
  while (arange);

  if (unit->arange.high == 0)
    {
      /* This is the first address range: store it in unit->arange.  */
      unit->arange.next = 0;
      unit->arange.low = low_pc;
      unit->arange.high = high_pc;
      return;
    }

  /* Need to allocate a new arange and insert it into the arange list.  */
  arange = (struct arange *)bfd_zalloc (unit->abfd, (bfd_size_type) sizeof (*arange));
  arange->low = low_pc;
  arange->high = high_pc;

  arange->next = unit->arange.next;
  unit->arange.next = arange;
}

/* Decode the line number information for UNIT.  */
struct line_info_table* decode_line_info (struct comp_unit *unit, struct dwarf2_debug *stash )
{
  bfd *abfd = unit->abfd;
  struct line_info_table* table;
  char *line_ptr;
  char *line_end;
  struct line_head lh;
  unsigned int i, bytes_read, offset_size;
  char *cur_file, *cur_dir;
  unsigned char op_code, extended_op, adj_opcode;
  bfd_size_type amt;

  if (! stash->dwarf_line_buffer)
    {
      asection *msec;

      msec = bfd_get_section_by_name (abfd, ".debug_line");
      if (! msec)
	{
	  (*_bfd_error_handler) (("Dwarf Error: Can't find .debug_line section."));
	  bfd_set_error (bfd_error_bad_value);
	  return 0;
	}

      stash->dwarf_line_size = msec->_raw_size;
      stash->dwarf_line_buffer = (char *) bfd_alloc (abfd, msec->_raw_size);
      if (! stash->dwarf_line_buffer)
	return 0;

      if (! bfd_get_section_contents (abfd, msec, stash->dwarf_line_buffer,
				      (bfd_vma) 0, msec->_raw_size))
	return 0;

      /* FIXME: We ought to apply the relocs against this section before
	 we process it...  */
    }

  /* Since we are using un-relocated data, it is possible to get a bad value
     for the line_offset.  Validate it here so that we won't get a segfault
     below.  */
  if (unit->line_offset >= stash->dwarf_line_size)
    {
      (*_bfd_error_handler) (("Dwarf Error: Line offset (%lu) greater than or equal to .debug_line size (%lu)."),
			     unit->line_offset, stash->dwarf_line_size);
      bfd_set_error (bfd_error_bad_value);
      return 0;
    }

  amt = sizeof (struct line_info_table);
  table = (struct line_info_table*) bfd_alloc (abfd, amt);
  table->abfd = abfd;
  table->comp_dir = unit->comp_dir;

  table->num_files = 0;
  table->files = NULL;

  table->num_dirs = 0;
  table->dirs = NULL;

  table->files = NULL;
  table->last_line = NULL;

  line_ptr = stash->dwarf_line_buffer + unit->line_offset;

  /* Read in the prologue.  */
  lh.total_length = read_4_bytes (abfd, line_ptr);
  line_ptr += 4;
  offset_size = 4;
  if (lh.total_length == 0xffffffff)
    {
      lh.total_length = read_8_bytes (abfd, line_ptr);
      line_ptr += 8;
      offset_size = 8;
    }
  else if (lh.total_length == 0 && unit->addr_size == 8)
    {
      /* Handle (non-standard) 64-bit DWARF2 formats.  */
      lh.total_length = read_4_bytes (abfd, line_ptr);
      line_ptr += 4;
      offset_size = 8;
    }
  line_end = line_ptr + lh.total_length;
  lh.version = read_2_bytes (abfd, line_ptr);
  line_ptr += 2;
  if (offset_size == 4)
    lh.prologue_length = read_4_bytes (abfd, line_ptr);
  else
    lh.prologue_length = read_8_bytes (abfd, line_ptr);
  line_ptr += offset_size;
  lh.minimum_instruction_length = read_1_byte (abfd, line_ptr);
  line_ptr += 1;
  lh.default_is_stmt = read_1_byte (abfd, line_ptr);
  line_ptr += 1;
  lh.line_base = read_1_signed_byte (abfd, line_ptr);
  line_ptr += 1;
  lh.line_range = read_1_byte (abfd, line_ptr);
  line_ptr += 1;
  lh.opcode_base = read_1_byte (abfd, line_ptr);
  line_ptr += 1;
  amt = lh.opcode_base * sizeof (unsigned char);
  lh.standard_opcode_lengths = (unsigned char *) bfd_alloc (abfd, amt);

  lh.standard_opcode_lengths[0] = 1;

  for (i = 1; i < lh.opcode_base; ++i)
    {
      lh.standard_opcode_lengths[i] = read_1_byte (abfd, line_ptr);
      line_ptr += 1;
    }

  /* Read directory table.  */
  while ((cur_dir = read_string (abfd, line_ptr, &bytes_read)) != NULL)
    {
      line_ptr += bytes_read;

      if ((table->num_dirs % DIR_ALLOC_CHUNK) == 0)
	{
	  amt = table->num_dirs + DIR_ALLOC_CHUNK;
	  amt *= sizeof (char *);
	  table->dirs = (char **) bfd_realloc ((struct attr_abbrev *)table->dirs, amt);
	  if (! table->dirs)
	    return 0;
	}

      table->dirs[table->num_dirs++] = cur_dir;
    }

  line_ptr += bytes_read;

  /* Read file name table.  */
  while ((cur_file = read_string (abfd, line_ptr, &bytes_read)) != NULL)
    {
      line_ptr += bytes_read;

      if ((table->num_files % FILE_ALLOC_CHUNK) == 0)
	{
	  amt = table->num_files + FILE_ALLOC_CHUNK;
	  amt *= sizeof (struct fileinfo);
	  table->files = (struct fileinfo *) bfd_realloc ((struct attr_abbrev *)table->files, amt);
	  if (! table->files)
	    return 0;
	}

      table->files[table->num_files].name = cur_file;
      table->files[table->num_files].dir =
	read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
      line_ptr += bytes_read;
      table->files[table->num_files].time =
	read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
      line_ptr += bytes_read;
      table->files[table->num_files].size =
	read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
      line_ptr += bytes_read;
      table->num_files++;
    }

  line_ptr += bytes_read;

  /* Read the statement sequences until there's nothing left.  */
  while (line_ptr < line_end)
    {
      /* State machine registers.  */
      bfd_vma address = 0;
      char* filename = concat_filename (table, 1);
      unsigned int line = 1;
      unsigned int column = 0;
      int is_stmt = lh.default_is_stmt;
      int basic_block = 0;
      int end_sequence = 0, need_low_pc = 1;
      bfd_vma low_pc = 0;

      /* Decode the table.  */
      while (! end_sequence)
	{
	  op_code = read_1_byte (abfd, line_ptr);
	  line_ptr += 1;

	  if (op_code >= lh.opcode_base)
	    {		/* Special operand.  */
	      adj_opcode = op_code - lh.opcode_base;
	      address += (adj_opcode / lh.line_range)
		* lh.minimum_instruction_length;
	      line += lh.line_base + (adj_opcode % lh.line_range);
	      /* Append row to matrix using current values.  */
	      add_line_info (table, address, filename, line, column, 0);
	      basic_block = 1;
	      if (need_low_pc)
		{
		  need_low_pc = 0;
		  low_pc = address;
		}
	    }
	  else switch (op_code)
	    {
	    case DW_LNS_extended_op:
	      line_ptr += 1;	/* Ignore length.  */
	      extended_op = read_1_byte (abfd, line_ptr);
	      line_ptr += 1;
	      switch (extended_op)
		{
		case DW_LNE_end_sequence:
		  end_sequence = 1;
		  add_line_info (table, address, filename, line, column,
				 end_sequence);
		  if (need_low_pc)
		    {
		      need_low_pc = 0;
		      low_pc = address;
		    }
		  arange_add (unit, low_pc, address);
		  break;
		case DW_LNE_set_address:
		  address = read_address (unit, line_ptr);
		  line_ptr += unit->addr_size;
		  break;
		case DW_LNE_define_file:
		  cur_file = read_string (abfd, line_ptr, &bytes_read);
		  line_ptr += bytes_read;
		  if ((table->num_files % FILE_ALLOC_CHUNK) == 0)
		    {
		      amt = table->num_files + FILE_ALLOC_CHUNK;
		      amt *= sizeof (struct fileinfo);
		      table->files =
			(struct fileinfo *) bfd_realloc ((struct attr_abbrev *)table->files, amt);
		      if (! table->files)
			return 0;
		    }
		  table->files[table->num_files].name = cur_file;
		  table->files[table->num_files].dir =
		    read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
		  line_ptr += bytes_read;
		  table->files[table->num_files].time =
		    read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
		  line_ptr += bytes_read;
		  table->files[table->num_files].size =
		    read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
		  line_ptr += bytes_read;
		  table->num_files++;
		  break;
		default:
		  (*_bfd_error_handler) (("Dwarf Error: mangled line number section."));
		  bfd_set_error (bfd_error_bad_value);
		  return 0;
		}
	      break;
	    case DW_LNS_copy:
	      add_line_info (table, address, filename, line, column, 0);
	      basic_block = 0;
	      if (need_low_pc)
		{
		  need_low_pc = 0;
		  low_pc = address;
		}
	      break;
	    case DW_LNS_advance_pc:
	      address += lh.minimum_instruction_length
		* read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
	      line_ptr += bytes_read;
	      break;
	    case DW_LNS_advance_line:
	      line += read_signed_leb128 (abfd, line_ptr, &bytes_read);
	      line_ptr += bytes_read;
	      break;
	    case DW_LNS_set_file:
	      {
		unsigned int file;

		/* The file and directory tables are 0 based, the references
		   are 1 based.  */
		file = read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
		line_ptr += bytes_read;
		filename = concat_filename (table, file);
		break;
	      }
	    case DW_LNS_set_column:
	      column = read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
	      line_ptr += bytes_read;
	      break;
	    case DW_LNS_negate_stmt:
	      is_stmt = (!is_stmt);
	      break;
	    case DW_LNS_set_basic_block:
	      basic_block = 1;
	      break;
	    case DW_LNS_const_add_pc:
	      address += lh.minimum_instruction_length
		      * ((255 - lh.opcode_base) / lh.line_range);
	      break;
	    case DW_LNS_fixed_advance_pc:
	      address += read_2_bytes (abfd, line_ptr);
	      line_ptr += 2;
	      break;
	    default:
	      {  /* Unknown standard opcode, ignore it.  */
		int i;
		for (i = 0; i < lh.standard_opcode_lengths[op_code]; i++)
		  {
		    (void) read_unsigned_leb128 (abfd, line_ptr, &bytes_read);
		    line_ptr += bytes_read;
		  }
	      }
	    }
	}
    }

  return table;
}

/* If ADDR is within TABLE set the output parameters and return true,
   otherwise return false.  The output parameters, FILENAME_PTR and
   LINENUMBER_PTR, are pointers to the objects to be filled in.  */
bool lookup_address_in_line_info_table (
     struct line_info_table* table,
     bfd_vma addr,
     struct funcinfo *function,
     const char **filename_ptr,
     unsigned int *linenumber_ptr )
{
  struct line_info* next_line = table->last_line;
  struct line_info* each_line;

  if (!next_line)
    return false;

  each_line = next_line->prev_line;

  while (each_line && next_line)
    {
      if (!each_line->end_sequence
	  && addr >= each_line->address && addr < next_line->address)
	{
	  /* If this line appears to span functions, and addr is in the
	     later function, return the first line of that function instead
	     of the last line of the earlier one.  This check is for GCC
	     2.95, which emits the first line number for a function late.  */
	  if (function != NULL
	      && each_line->address < function->low
	      && next_line->address > function->low)
	    {
	      *filename_ptr = next_line->filename;
	      *linenumber_ptr = next_line->line;
	    }
	  else
	    {
	      *filename_ptr = each_line->filename;
	      *linenumber_ptr = each_line->line;
	    }
	  return true;
	}
      next_line = each_line;
      each_line = each_line->prev_line;
    }

  /* At this point each_line is NULL but next_line is not.  If we found the
     containing function in this compilation unit, return the first line we
     have a number for.  This is also for compatibility with GCC 2.95.  */
  if (function != NULL)
    {
      *filename_ptr = next_line->filename;
      *linenumber_ptr = next_line->line;
      return true;
    }

  return false;
}

/* Function table functions.  */

/* If ADDR is within TABLE, set FUNCTIONNAME_PTR, and return true.  */
bool lookup_address_in_function_table (
     struct funcinfo* table,
     bfd_vma addr,
     struct funcinfo** function_ptr,
     const char **functionname_ptr )
{
  struct funcinfo* each_func;

  for (each_func = table;
       each_func;
       each_func = each_func->prev_func)
    {
      if (addr >= each_func->low && addr < each_func->high)
	{
	  *functionname_ptr = each_func->name;
	  *function_ptr = each_func;
	  return true;
	}
    }

  return false;
}

/* DWARF2 Compilation unit functions.  */

/* Scan over each die in a comp. unit looking for functions to add
   to the function table.  */
bool scan_unit_for_functions ( struct comp_unit *unit )
{
  bfd *abfd = unit->abfd;
  char *info_ptr = unit->first_child_die_ptr;
  int nesting_level = 1;

  while (nesting_level)
    {
      unsigned int abbrev_number, bytes_read, i;
      struct abbrev_info *abbrev;
      struct attribute attr;
      struct funcinfo *func;
      char* name = 0;

      abbrev_number = read_unsigned_leb128 (abfd, info_ptr, &bytes_read);
      info_ptr += bytes_read;

      if (! abbrev_number)
	{
	  nesting_level--;
	  continue;
	}

      abbrev = lookup_abbrev (abbrev_number,unit->abbrevs);
      if (! abbrev)
	{
	  (*_bfd_error_handler) (("Dwarf Error: Could not find abbrev number %u."),
			     abbrev_number);
	  bfd_set_error (bfd_error_bad_value);
	  return false;
	}

      if (abbrev->tag == DW_TAG_subprogram)
	{
	  bfd_size_type amt = sizeof (struct funcinfo);
	  func = (struct funcinfo *) bfd_zalloc (abfd, amt);
	  func->prev_func = unit->function_table;
	  unit->function_table = func;
	}
      else
	func = NULL;

      for (i = 0; i < abbrev->num_attrs; ++i)
	{
	  info_ptr = read_attribute (&attr, &abbrev->attrs[i], unit, info_ptr);

	  if (func)
	    {
	      switch (attr.name)
		{
		case DW_AT_name:

		  name = DW_STRING (&attr);

		  /* Prefer DW_AT_MIPS_linkage_name over DW_AT_name.  */
		  if (func->name == NULL)
		    func->name = DW_STRING (&attr);
		  break;

		case DW_AT_MIPS_linkage_name:
		  func->name = DW_STRING (&attr);
		  break;

		case DW_AT_low_pc:
		  func->low = DW_ADDR (&attr);
		  break;

		case DW_AT_high_pc:
		  func->high = DW_ADDR (&attr);
		  break;

		default:
		  break;
		}
	    }
	  else
	    {
	      switch (attr.name)
		{
		case DW_AT_name:
		  name = DW_STRING (&attr);
		  break;

		default:
		  break;
		}
	    }
	}

      if (abbrev->has_children)
	nesting_level++;
    }

  return true;
}

/* Look for a RELA relocation to be applied on OFFSET of section SEC,
   and return the addend if such a relocation is found.  Since this is
   only used to find relocations referring to the .debug_abbrev
   section, we make sure the relocation refers to this section, but
   this is not strictly necessary, and it can probably be safely
   removed if needed.  However, it is important to note that this
   function only returns the addend, it doesn't serve the purpose of
   applying a generic relocation.

   If no suitable relocation is found, or if it is not a real RELA
   relocation, this function returns 0.  */
bfd_vma find_rela_addend (
     bfd* abfd,
     asection* sec, 
     bfd_size_type offset,
     asymbol** syms )
{
  long reloc_size = bfd_get_reloc_upper_bound (abfd, sec);
  arelent **relocs = NULL;
  long reloc_count, relc;

  if (reloc_size <= 0)
    return 0;

  relocs = (arelent **) bfd_malloc ((bfd_size_type) reloc_size);
  if (relocs == NULL)
    return 0;

  reloc_count = bfd_canonicalize_reloc (abfd, sec, relocs, syms);

  if (reloc_count <= 0)
    {
      free (relocs);
      return 0;
    }

  for (relc = 0; relc < reloc_count; relc++)
    if (relocs[relc]->address == offset
	&& (*relocs[relc]->sym_ptr_ptr)->flags & BSF_SECTION_SYM
	&& strcmp ((*relocs[relc]->sym_ptr_ptr)->name,
		   ".debug_abbrev") == 0)
      {
	bfd_vma addend = (relocs[relc]->howto->partial_inplace
			  ? 0 : relocs[relc]->addend);
	free (relocs);
	return addend;
      }

  free (relocs);
  return 0;
}

/* Parse a DWARF2 compilation unit starting at INFO_PTR.  This
   includes the compilation unit header that proceeds the DIE's, but
   does not include the length field that preceeds each compilation
   unit header.  END_PTR points one past the end of this comp unit.
   OFFSET_SIZE is the size of DWARF2 offsets (either 4 or 8 bytes).

   This routine does not read the whole compilation unit; only enough
   to get to the line number information for the compilation unit.  */
struct comp_unit *parse_comp_unit ( bfd* abfd, struct dwarf2_debug *stash, bfd_vma unit_length, unsigned int offset_size )
{
	struct comp_unit* unit;
	unsigned int version;
	bfd_vma abbrev_offset = 0;
	unsigned int addr_size;
	struct abbrev_info** abbrevs;
	unsigned int abbrev_number, bytes_read, i;
	struct abbrev_info *abbrev;
	struct attribute attr;
	char *info_ptr = stash->info_ptr;
	char *end_ptr = info_ptr + unit_length;
	bfd_size_type amt;
	bfd_size_type off;

	version = read_2_bytes (abfd, info_ptr);
	info_ptr += 2;
	assert (offset_size == 4 || offset_size == 8);

	if (offset_size == 4)
		abbrev_offset = read_4_bytes (abfd, info_ptr);
	else
		abbrev_offset = read_8_bytes (abfd, info_ptr);

	/* The abbrev offset is generally a relocation pointing to
	 .debug_abbrev+offset.  On RELA targets, we have to find the
	 relocation and extract the addend to obtain the actual
	 abbrev_offset, so do it here.  */
	off = info_ptr - stash->sec_info_ptr;
	abbrev_offset += find_rela_addend (abfd, stash->sec, off, stash->syms);
	info_ptr += offset_size;
	addr_size = read_1_byte (abfd, info_ptr);
	info_ptr += 1;

	if (version != 2)
	{
		(*_bfd_error_handler) (("Dwarf Error: found dwarf version '%u', this reader only handles version 2 information."), version);
		bfd_set_error (bfd_error_bad_value);
		return 0;
	}

	if (addr_size > sizeof (bfd_vma))
	{
		(*_bfd_error_handler) (("Dwarf Error: found address size '%u', this reader can not handle sizes greater than '%u'."), addr_size, (unsigned int) sizeof (bfd_vma));
		bfd_set_error (bfd_error_bad_value);
		return 0;
	}

	if (addr_size != 2 && addr_size != 4 && addr_size != 8)
	{
		(*_bfd_error_handler) ("Dwarf Error: found address size '%u', this reader can only handle address sizes '2', '4' and '8'.", addr_size);
		bfd_set_error (bfd_error_bad_value);
		return 0;
	}

	/* Read the abbrevs for this compilation unit into a table.  */
	abbrevs = read_abbrevs (abfd, abbrev_offset, stash);
	if (! abbrevs)
		return 0;

	abbrev_number = read_unsigned_leb128 (abfd, info_ptr, &bytes_read);
	info_ptr += bytes_read;
	if (! abbrev_number)
	{
		(*_bfd_error_handler) (("Dwarf Error: Bad abbrev number: %u."),	abbrev_number);
		bfd_set_error (bfd_error_bad_value);
		return 0;
	}

	abbrev = lookup_abbrev (abbrev_number, abbrevs);
	if (! abbrev)
	{
		(*_bfd_error_handler) (("Dwarf Error: Could not find abbrev number %u."), abbrev_number);
		bfd_set_error (bfd_error_bad_value);
		return 0;
	}

	amt = sizeof (struct comp_unit);
	unit = (struct comp_unit*) bfd_zalloc (abfd, amt);
	unit->abfd = abfd;
	unit->addr_size = addr_size;
	unit->offset_size = offset_size;
	unit->abbrevs = abbrevs;
	unit->end_ptr = end_ptr;
	unit->stash = stash;

	for (i = 0; i < abbrev->num_attrs; ++i)
	{
		info_ptr = read_attribute (&attr, &abbrev->attrs[i], unit, info_ptr);

     	 /* Store the data if it is of an attribute we want to keep in a
			partial symbol table.  */
		switch (attr.name)
		{
			case DW_AT_stmt_list:
				unit->stmtlist = 1;
				unit->line_offset = DW_UNSND (&attr);
				break;

			case DW_AT_name:
				unit->name = DW_STRING (&attr);
				break;

			case DW_AT_low_pc:
				unit->arange.low = DW_ADDR (&attr);
				break;

			case DW_AT_high_pc:
				unit->arange.high = DW_ADDR (&attr);
				break;

			case DW_AT_comp_dir:
				{
					char* comp_dir = DW_STRING (&attr);
					if (comp_dir)
					{
						/* Irix 6.2 native cc prepends <machine>.: to the compilation
						directory, get rid of it.  */
						char *cp = (char*) strchr (comp_dir, ':');

						if (cp && cp != comp_dir && cp[-1] == '.' && cp[1] == '/')
							comp_dir = cp + 1;
					}
					unit->comp_dir = comp_dir;
					break;
				}

			default:
			break;
		}
    }

	unit->first_child_die_ptr = info_ptr;
	return unit;
}

/* Return true if UNIT contains the address given by ADDR.  */
bool comp_unit_contains_address( struct comp_unit* unit, bfd_vma addr )
{
  struct arange *arange;

  if (unit->error)
    return 0;

  arange = &unit->arange;
  do
    {
      if (addr >= arange->low && addr < arange->high)
	return 1;
      arange = arange->next;
    }
  while (arange);

  return 0;
}

/* If UNIT contains ADDR, set the output parameters to the values for
   the line containing ADDR.  The output parameters, FILENAME_PTR,
   FUNCTIONNAME_PTR, and LINENUMBER_PTR, are pointers to the objects
   to be filled in.

   Return true of UNIT contains ADDR, and no errors were encountered;
   false otherwise.  */
bool comp_unit_find_nearest_line (
     struct comp_unit* unit,
     bfd_vma addr,
     const char **filename_ptr,
     const char **functionname_ptr,
     unsigned int *linenumber_ptr,
     struct dwarf2_debug *stash )
{
  bool line_p;
  bool func_p;
  struct funcinfo *function;

  if (unit->error)
    return false;

  if (! unit->line_table)
    {
      if (! unit->stmtlist)
	{
	  unit->error = 1;
	  return false;
	}

      unit->line_table = decode_line_info (unit, stash);

      if (! unit->line_table)
	{
	  unit->error = 1;
	  return false;
	}

      if (unit->first_child_die_ptr < unit->end_ptr
          && ! scan_unit_for_functions (unit))
	{
	  unit->error = 1;
	  return false;
	}
    }

  function = NULL;
  func_p = lookup_address_in_function_table (unit->function_table,
					     addr,
					     &function,
					     functionname_ptr);
  line_p = lookup_address_in_line_info_table (unit->line_table,
					      addr,
					      function,
					      filename_ptr,
					      linenumber_ptr);
  return line_p || func_p;
}

/* Locate a section in a BFD containing debugging info.  The search starts from the
   section after AFTER_SEC, or from the first section in the BFD if AFTER_SEC is
   NULL.  The search works by examining the names of the sections.  There are two
   permissiable names.  The first is .debug_info.  This is the standard DWARF2 name.
   The second is a prefix .gnu.linkonce.wi.  This is a variation on the .debug_info
   section which has a checksum describing the contents appended onto the name.  This
   allows the linker to identify and discard duplicate debugging sections for
   different compilation units.  */
#define DWARF2_DEBUG_INFO ".debug_info"
#define GNU_LINKONCE_INFO ".gnu.linkonce.wi."

asection *find_debug_info ( bfd * abfd, asection * after_sec )
{
  asection * msec;

  if (after_sec)
    msec = after_sec->next;
  else
    msec = abfd->sections;

  while (msec)
    {
      if (strcmp (msec->name, DWARF2_DEBUG_INFO) == 0)
	return msec;

      if (strncmp (msec->name, GNU_LINKONCE_INFO, strlen (GNU_LINKONCE_INFO)) == 0)
	return msec;

      msec = msec->next;
    }

  return NULL;
}

/* The DWARF2 version of find_nearest line.  Return true if the line
   is found without error.  ADDR_SIZE is the number of bytes in the
   initial .debug_info length field and in the abbreviation offset.
   You may use zero to indicate that the default value should be
   used.  */
bool _bfd_dwarf2_find_nearest_line (
     bfd *abfd,
     asection *section,
     asymbol **symbols,
     bfd_vma offset,
     const char **filename_ptr,
     const char **functionname_ptr,
     unsigned int *linenumber_ptr,
     unsigned int addr_size,
     PTR *pinfo )
{
	/* Read each compilation unit from the section .debug_info, and check
	to see if it contains the address we are searching for.  If yes,
	lookup the address, and return the line number info.  If no, go
	on to the next compilation unit.

	We keep a list of all the previously read compilation units, and
	a pointer to the next un-read compilation unit.  Check the
	previously read units before reading more.  */
	struct dwarf2_debug *stash = (struct dwarf2_debug *) *pinfo;

	/* What address are we looking for?  */
	bfd_vma addr = offset + section->vma;

	struct comp_unit* each;

	*filename_ptr = NULL;
	*functionname_ptr = NULL;
	*linenumber_ptr = 0;

  /* The DWARF2 spec says that the initial length field, and the
     offset of the abbreviation table, should both be 4-byte values.
     However, some compilers do things differently.  */
	if (addr_size == 0)
		addr_size = 4;
	assert(addr_size == 4 || addr_size == 8);

	if (! stash)
	{
		bfd_size_type total_size;
		asection *msec;
		bfd_size_type amt = sizeof (struct dwarf2_debug);

		stash = (struct dwarf2_debug*) bfd_zalloc (abfd, amt);
		if (! stash)
			return false;

		*pinfo = (PTR) stash;

		msec = find_debug_info (abfd, NULL);
		if (! msec)
		/* No dwarf2 info.  Note that at this point the stash
		has been allocated, but contains zeros, this lets
		future calls to this function fail quicker.  */
		return false;

		/* There can be more than one DWARF2 info section in a BFD these days.
		Read them all in and produce one large stash.  We do this in two
		passes - in the first pass we just accumulate the section sizes.
		In the second pass we read in the section's contents.  The allows
		us to avoid reallocing the data as we add sections to the stash.  */
		for (total_size = 0; msec; msec = find_debug_info (abfd, msec))
		{
			total_size += msec->_raw_size;
		}

		stash->info_ptr = (char *) bfd_alloc (abfd, total_size);
		if (stash->info_ptr == NULL)
			return false;

		stash->info_ptr_end = stash->info_ptr;

		for (msec = find_debug_info (abfd, NULL); msec; msec = find_debug_info (abfd, msec))
		{
			bfd_size_type size;
			bfd_size_type start;

			size = msec->_raw_size;
			if (size == 0)
				continue;

			start = stash->info_ptr_end - stash->info_ptr;

			if (! bfd_get_section_contents (abfd, msec, stash->info_ptr + start, (bfd_vma) 0, size))
				continue;

			stash->info_ptr_end = stash->info_ptr + start + size;
		}

		assert (stash->info_ptr_end == stash->info_ptr + total_size);

		stash->sec = find_debug_info (abfd, NULL);
		stash->sec_info_ptr = stash->info_ptr;
		stash->syms = symbols;
    }

	/* FIXME: There is a problem with the contents of the
	 .debug_info section.  The 'low' and 'high' addresses of the
	 comp_units are computed by relocs against symbols in the
	 .text segment.  We need these addresses in order to determine
	 the nearest line number, and so we have to resolve the
	 relocs.  There is a similar problem when the .debug_line
	 section is processed as well (e.g., there may be relocs
	 against the operand of the DW_LNE_set_address operator).

	 Unfortunately getting hold of the reloc information is hard...

	 For now, this means that disassembling object files (as
	 opposed to fully executables) does not always work as well as
	 we would like.  */

	/* A null info_ptr indicates that there is no dwarf2 info
	 (or that an error occured while setting up the stash).  */
	if (! stash->info_ptr)
		return false;

	/* Check the previously read comp. units first.  */
	for (each = stash->all_comp_units; each; each = each->next_unit)
	{
		if (comp_unit_contains_address (each, addr))
		{
			return comp_unit_find_nearest_line (each, addr, filename_ptr, functionname_ptr, linenumber_ptr, stash);
		}
	}

	/* Read each remaining comp. units checking each as they are read.  */
	while (stash->info_ptr < stash->info_ptr_end)
	{
		bfd_vma length;
		bool found;
		unsigned int offset_size = addr_size;

		if (addr_size == 4)
		{
			length = read_4_bytes (abfd, stash->info_ptr);
			if (length == 0xffffffff)
			{
				offset_size = 8;
				length = read_8_bytes (abfd, stash->info_ptr + 4);
				stash->info_ptr += 8;
			}
		}
		else
		{
			length = read_8_bytes (abfd, stash->info_ptr);
		}

		stash->info_ptr += addr_size;

		if (length > 0)
		{
			each = parse_comp_unit (abfd, stash, length, offset_size);
			stash->info_ptr += length;

			if ((bfd_vma) (stash->info_ptr - stash->sec_info_ptr) == stash->sec->_raw_size)
			{
				stash->sec = find_debug_info (abfd, stash->sec);
				stash->sec_info_ptr = stash->info_ptr;
			}

			if (each)
			{
				each->next_unit = stash->all_comp_units;
				stash->all_comp_units = each;

				/* DW_AT_low_pc and DW_AT_high_pc are optional for
				compilation units.  If we don't have them (i.e.,
				unit->high == 0), we need to consult the line info
				table to see if a compilation unit contains the given
				address.  */
				if (each->arange.high > 0)
				{
					if (comp_unit_contains_address (each, addr))
					{
						return comp_unit_find_nearest_line (each, addr,
										   filename_ptr,
										   functionname_ptr,
										   linenumber_ptr,
										   stash);
					}
				}
				else
				{
					found = comp_unit_find_nearest_line (each, addr,
									   filename_ptr,
									   functionname_ptr,
									   linenumber_ptr,
									   stash);
					if (found)
						return true;
				}
			}
		}
	}
	return false;
}

void _bfd_default_error_handler VPARAMS ((const char *s, ...))
{
  if (_bfd_error_program_name != NULL)
    fprintf (stderr, "%s: ", _bfd_error_program_name);
  else
    fprintf (stderr, "BFD: ");

  fprintf (stderr, "\n");
}

PTR bfd_alloc (bfd *abfd, bfd_size_type size)
{
  PTR ret;

  ret = (PTR)malloc((unsigned long) size);
  if (ret == NULL)
  {
    bfd_set_error (bfd_error_no_memory);
  }

  return ret;
}

PTR bfd_malloc (bfd_size_type size)
{
  PTR ret;

  ret = (PTR)malloc((unsigned long) size);
  if (ret == NULL)
  {
    bfd_set_error (bfd_error_no_memory);
  }

  return ret;
}

PTR bfd_realloc (struct attr_abbrev *abbr, bfd_size_type size)
{
  return bfd_alloc((struct _bfd *)abbr, size);
}

PTR bfd_zalloc (bfd *abfd, bfd_size_type size)
{
  PTR res;

  res = bfd_alloc (abfd, size);
  if (res)
    memset (res, 0, (size_t) size);
  return res;
}

bfd_error_type bfd_error = bfd_error_no_error;

const char *const bfd_errmsgs[] =
{
  "No error",
  "System call error",
  "Invalid bfd target",
  "File in wrong format",
  "Archive object file in wrong format",
  "Invalid operation",
  "Memory exhausted",
  "No symbols",
  "Archive has no index; run ranlib to add one",
  "No more archived files",
  "Malformed archive",
  "File format not recognized",
  "File format is ambiguous",
  "Section has no contents",
  "Nonrepresentable section on output",
  "Symbol needs debug section which does not exist",
  "Bad value",
  "File truncated",
  "File too big",
  "#<Invalid error code>"
};

void bfd_set_error (bfd_error_type error_tag)
{
  bfd_error = error_tag;
}

bfd_error_type bfd_get_error ()
{
  return bfd_error;
}

const char *bfd_errmsg (bfd_error_type error_tag)
{
  if ((((int) error_tag < (int) bfd_error_no_error) ||
       ((int) error_tag > (int) bfd_error_invalid_error_code)))
    error_tag = bfd_error_invalid_error_code;/* sanity check */

  return (bfd_errmsgs[(int)error_tag]);
}

long bfd_canonicalize_reloc ( bfd *abfd, sec_ptr asect, arelent **location, asymbol **symbols )
{
  if (abfd->format != bfd_object)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return -1;
    }

/* --- Replaced by Jack Zhao on 2004-6-1---
  return BFD_SEND (abfd, _bfd_canonicalize_reloc, (abfd, asect, location, symbols));
*/
/* The new is: */
  return -1;
/*----------------------------------------------------*/
}

long bfd_get_reloc_upper_bound ( bfd *abfd, sec_ptr asect )
{
  if (abfd->format != bfd_object)
    {
      bfd_set_error (bfd_error_invalid_operation);
      return -1;
    }

/* --- Replaced by Jack Zhao on 2004-6-1---
  return BFD_SEND (abfd, _get_reloc_upper_bound, (abfd, asect));
*/
/* The new is: */
  return -1;
/*----------------------------------------------------*/
}

