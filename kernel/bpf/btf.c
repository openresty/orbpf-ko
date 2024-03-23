/* Copyright (C) by OpenResty Inc. All rights reserved. */
 

#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/bpf_perf_event.h>
#include <uapi/linux/types.h>
#include <linux/seq_file.h>
#include <linux/compiler.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/idr.h>
#include <linux/sort.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>



#include <linux/perf_event.h>
#include <linux/bsearch.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <net/sock.h>
#include <linux/orbpf_config_begin.h>  













































































































































#define BITS_PER_U128 (sizeof(u64) * BITS_PER_BYTE * 2)
#define BITS_PER_BYTE_MASK (BITS_PER_BYTE - 1)
#define BITS_PER_BYTE_MASKED(bits) ((bits) & BITS_PER_BYTE_MASK)
#define BITS_ROUNDDOWN_BYTES(bits) ((bits) >> 3)
#define BITS_ROUNDUP_BYTES(bits) \
	(BITS_ROUNDDOWN_BYTES(bits) + !!BITS_PER_BYTE_MASKED(bits))

#define BTF_INFO_MASK 0x9f00ffff
#define BTF_INT_MASK 0x0fffffff
#define BTF_TYPE_ID_VALID(type_id) ((type_id) <= BTF_MAX_TYPE)
#define BTF_STR_OFFSET_VALID(name_off) ((name_off) <= BTF_MAX_NAME_OFFSET)





#define BTF_MAX_SIZE (16 * 1024 * 1024)

#define for_each_member_from(i, from, struct_type, member)		\
	for (i = from, member = btf_type_member(struct_type) + from;	\
	     i < btf_type_vlen(struct_type);				\
	     i++, member++)

#define for_each_vsi_from(i, from, struct_type, member)				\
	for (i = from, member = btf_type_var_secinfo(struct_type) + from;	\
	     i < btf_type_vlen(struct_type);					\
	     i++, member++)




#if 1
DEFINE_IDR(orbpf_btf_idr);
DEFINE_SPINLOCK(orbpf_btf_idr_lock);

struct idr *orbpf_btf_idr_ptr = &orbpf_btf_idr;
spinlock_t *orbpf_btf_idr_lock_ptr = &orbpf_btf_idr_lock;
#endif

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;  
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct rcu_head rcu;

	 
	struct btf *base_btf;
	u32 start_id;  
	u32 start_str_off;  
	char name[MODULE_NAME_LEN];
	bool kernel_btf;
};

enum verifier_phase {
	CHECK_META,
	CHECK_TYPE,
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum visit_state {
	NOT_VISITED,
	VISITED,
	RESOLVED,
};

enum resolve_mode {
	RESOLVE_TBD,	 
	RESOLVE_PTR,	 
	RESOLVE_STRUCT_OR_ARRAY,	


};

#define MAX_RESOLVE_DEPTH 32

struct btf_sec_info {
	u32 off;
	u32 len;
};

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[MAX_RESOLVE_DEPTH];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

static const char * const btf_kind_str[NR_BTF_KINDS] = {
	[BTF_KIND_UNKN]		= "UNKNOWN",
	[BTF_KIND_INT]		= "INT",
	[BTF_KIND_PTR]		= "PTR",
	[BTF_KIND_ARRAY]	= "ARRAY",
	[BTF_KIND_STRUCT]	= "STRUCT",
	[BTF_KIND_UNION]	= "UNION",
	[BTF_KIND_ENUM]		= "ENUM",
	[BTF_KIND_FWD]		= "FWD",
	[BTF_KIND_TYPEDEF]	= "TYPEDEF",
	[BTF_KIND_VOLATILE]	= "VOLATILE",
	[BTF_KIND_CONST]	= "CONST",
	[BTF_KIND_RESTRICT]	= "RESTRICT",
	[BTF_KIND_FUNC]		= "FUNC",
	[BTF_KIND_FUNC_PROTO]	= "FUNC_PROTO",
	[BTF_KIND_VAR]		= "VAR",
	[BTF_KIND_DATASEC]	= "DATASEC",
	[BTF_KIND_FLOAT]	= "FLOAT",
};

const char *btf_type_str(const struct btf_type *t)
{
	return btf_kind_str[BTF_INFO_KIND(t->info)];
}

 
#define BTF_SHOW_OBJ_SAFE_SIZE		32








#define BTF_SHOW_OBJ_BASE_TYPE_SIZE	16

 
#define BTF_SHOW_NAME_SIZE		80












































struct btf_show {
	u64 flags;
	void *target;	 
	void (*showfn)(struct btf_show *show, const char *fmt, va_list args);
	const struct btf *btf;
	 
	struct {
		u8 depth;
		u8 depth_to_show;
		u8 depth_check;
		u8 array_member:1,
		   array_terminated:1;
		u16 array_encoding;
		u32 type_id;
		int status;			 
		const struct btf_type *type;
		const struct btf_member *member;
		char name[BTF_SHOW_NAME_SIZE];	 
	} state;
	struct {
		u32 size;
		void *head;
		void *data;
		u8 safe[BTF_SHOW_OBJ_SAFE_SIZE];
	} obj;
};

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *env,
			  const struct btf_type *t,
			  u32 meta_left);
	int (*resolve)(struct btf_verifier_env *env,
		       const struct resolve_vertex *v);
	int (*check_member)(struct btf_verifier_env *env,
			    const struct btf_type *struct_type,
			    const struct btf_member *member,
			    const struct btf_type *member_type);
	int (*check_kflag_member)(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type);
	void (*log_details)(struct btf_verifier_env *env,
			    const struct btf_type *t);
	void (*show)(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offsets,
			 struct btf_show *show);
};

static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS];
static struct btf_type btf_void;

static int btf_resolve(struct btf_verifier_env *env,
		       const struct btf_type *t, u32 type_id);

static bool btf_type_is_modifier(const struct btf_type *t)
{
	









	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_CONST:
	case BTF_KIND_RESTRICT:
		return true;
	}

	return false;
}

bool btf_type_is_void(const struct btf_type *t)
{
	return t == &btf_void;
}

static bool btf_type_is_fwd(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_FWD;
}

static bool btf_type_nosize(const struct btf_type *t)
{
	return btf_type_is_void(t) || btf_type_is_fwd(t) ||
	       btf_type_is_func(t) || btf_type_is_func_proto(t);
}

static bool btf_type_nosize_or_null(const struct btf_type *t)
{
	return !t || btf_type_nosize(t);
}

static bool __btf_type_is_struct(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT;
}

static bool btf_type_is_array(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_ARRAY;
}

static bool btf_type_is_datasec(const struct btf_type *t)
{
	return BTF_INFO_KIND(t->info) == BTF_KIND_DATASEC;
}

u32 btf_nr_types(const struct btf *btf)
{
	u32 total = 0;

	while (btf) {
		total += btf->nr_types;
		btf = btf->base_btf;
	}

	return total;
}























const struct btf_type *btf_type_skip_modifiers(const struct btf *btf,
					       u32 id, u32 *res_id)
{
	const struct btf_type *t = btf_type_by_id(btf, id);

	while (btf_type_is_modifier(t)) {
		id = t->type;
		t = btf_type_by_id(btf, t->type);
	}

	if (res_id)
		*res_id = id;

	return t;
}






























static bool btf_type_is_resolve_source_only(const struct btf_type *t)
{
	return btf_type_is_var(t) ||
	       btf_type_is_datasec(t);
}

















static bool btf_type_needs_resolve(const struct btf_type *t)
{
	return btf_type_is_modifier(t) ||
	       btf_type_is_ptr(t) ||
	       btf_type_is_struct(t) ||
	       btf_type_is_array(t) ||
	       btf_type_is_var(t) ||
	       btf_type_is_datasec(t);
}

 
static bool btf_type_has_size(const struct btf_type *t)
{
	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_INT:
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
	case BTF_KIND_ENUM:
	case BTF_KIND_DATASEC:
	case BTF_KIND_FLOAT:
		return true;
	}

	return false;
}

static const char *btf_int_encoding_str(u8 encoding)
{
	if (encoding == 0)
		return "(none)";
	else if (encoding == BTF_INT_SIGNED)
		return "SIGNED";
	else if (encoding == BTF_INT_CHAR)
		return "CHAR";
	else if (encoding == BTF_INT_BOOL)
		return "BOOL";
	else
		return "UNKN";
}

static u32 btf_type_int(const struct btf_type *t)
{
	return *(u32 *)(t + 1);
}

static const struct btf_array *btf_type_array(const struct btf_type *t)
{
	return (const struct btf_array *)(t + 1);
}

static const struct btf_enum *btf_type_enum(const struct btf_type *t)
{
	return (const struct btf_enum *)(t + 1);
}

static const struct btf_var *btf_type_var(const struct btf_type *t)
{
	return (const struct btf_var *)(t + 1);
}

static const struct btf_kind_operations *btf_type_ops(const struct btf_type *t)
{
	return kind_ops[BTF_INFO_KIND(t->info)];
}

static bool btf_name_offset_valid(const struct btf *btf, u32 offset)
{
	if (!BTF_STR_OFFSET_VALID(offset))
		return false;

	while (offset < btf->start_str_off)
		btf = btf->base_btf;

	offset -= btf->start_str_off;
	return offset < btf->hdr.str_len;
}

static bool __btf_name_char_ok(char c, bool first, bool dot_ok)
{
	if ((first ? !isalpha(c) :
		     !isalnum(c)) &&
	    c != '_' &&
	    ((c == '.' && !dot_ok) ||
	      c != '.'))
		return false;
	return true;
}

static const char *btf_str_by_offset(const struct btf *btf, u32 offset)
{
	while (offset < btf->start_str_off)
		btf = btf->base_btf;

	offset -= btf->start_str_off;
	if (offset < btf->hdr.str_len)
		return &btf->strings[offset];

	return NULL;
}

static bool __btf_name_valid(const struct btf *btf, u32 offset, bool dot_ok)
{
	 
	const char *src = btf_str_by_offset(btf, offset);
	const char *src_limit;

	if (!__btf_name_char_ok(*src, true, dot_ok))
		return false;

	 
	src_limit = src + KSYM_NAME_LEN;
	src++;
	while (*src && src < src_limit) {
		if (!__btf_name_char_ok(*src, false, dot_ok))
			return false;
		src++;
	}

	return !*src;
}




static bool btf_name_valid_identifier(const struct btf *btf, u32 offset)
{
	return __btf_name_valid(btf, offset, false);
}

static bool btf_name_valid_section(const struct btf *btf, u32 offset)
{
	return __btf_name_valid(btf, offset, true);
}

static const char *__btf_name_by_offset(const struct btf *btf, u32 offset)
{
	const char *name;

	if (!offset)
		return "(anon)";

	name = btf_str_by_offset(btf, offset);
	return name ?: "(invalid-name-offset)";
}

const char *btf_name_by_offset(const struct btf *btf, u32 offset)
{
	return btf_str_by_offset(btf, offset);
}

const struct btf_type *btf_type_by_id(const struct btf *btf, u32 type_id)
{
	while (type_id < btf->start_id)
		btf = btf->base_btf;

	type_id -= btf->start_id;
	if (type_id >= btf->nr_types)
		return NULL;
	return btf->types[type_id];
}





static bool btf_type_int_is_regular(const struct btf_type *t)
{
	u8 nr_bits, nr_bytes;
	u32 int_data;

	int_data = btf_type_int(t);
	nr_bits = BTF_INT_BITS(int_data);
	nr_bytes = BITS_ROUNDUP_BYTES(nr_bits);
	if (BITS_PER_BYTE_MASKED(nr_bits) ||
	    BTF_INT_OFFSET(int_data) ||
	    (nr_bytes != sizeof(u8) && nr_bytes != sizeof(u16) &&
	     nr_bytes != sizeof(u32) && nr_bytes != sizeof(u64) &&
	     nr_bytes != (2 * sizeof(u64)))) {
		return false;
	}

	return true;
}












































 
static const struct btf_type *btf_type_skip_qualifiers(const struct btf *btf,
						       u32 id)
{
	const struct btf_type *t = btf_type_by_id(btf, id);

	while (btf_type_is_modifier(t) &&
	       BTF_INFO_KIND(t->info) != BTF_KIND_TYPEDEF) {
		t = btf_type_by_id(btf, t->type);
	}

	return t;
}

#define BTF_SHOW_MAX_ITER	10

#define BTF_KIND_BIT(kind)	(1ULL << kind)







static const char *btf_show_name(struct btf_show *show)
{
	 
	const char *array_suffixes = "[][][][][][][][][][]";
	const char *array_suffix = &array_suffixes[strlen(array_suffixes)];
	 
	const char *ptr_suffixes = "**********";
	const char *ptr_suffix = &ptr_suffixes[strlen(ptr_suffixes)];
	const char *name = NULL, *prefix = "", *parens = "";
	const struct btf_member *m = show->state.member;
	const struct btf_type *t = show->state.type;
	const struct btf_array *array;
	u32 id = show->state.type_id;
	const char *member = NULL;
	bool show_member = false;
	u64 kinds = 0;
	int i;

	show->state.name[0] = '\0';

	




	if (show->state.array_member)
		return "";

	 
	if (m) {
		member = btf_name_by_offset(show->btf, m->name_off);
		show_member = strlen(member) > 0;
		id = m->type;
	}

	






	t = btf_type_by_id(show->btf, id);
	if (!t)
		return "";

	





















	for (i = 0; i < BTF_SHOW_MAX_ITER; i++) {

		switch (BTF_INFO_KIND(t->info)) {
		case BTF_KIND_TYPEDEF:
			if (!name)
				name = btf_name_by_offset(show->btf,
							       t->name_off);
			kinds |= BTF_KIND_BIT(BTF_KIND_TYPEDEF);
			id = t->type;
			break;
		case BTF_KIND_ARRAY:
			kinds |= BTF_KIND_BIT(BTF_KIND_ARRAY);
			parens = "[";
			if (!t)
				return "";
			array = btf_type_array(t);
			if (array_suffix > array_suffixes)
				array_suffix -= 2;
			id = array->type;
			break;
		case BTF_KIND_PTR:
			kinds |= BTF_KIND_BIT(BTF_KIND_PTR);
			if (ptr_suffix > ptr_suffixes)
				ptr_suffix -= 1;
			id = t->type;
			break;
		default:
			id = 0;
			break;
		}
		if (!id)
			break;
		t = btf_type_skip_qualifiers(show->btf, id);
	}
	 
	if (i == BTF_SHOW_MAX_ITER)
		return "";

	if (!name)
		name = btf_name_by_offset(show->btf, t->name_off);

	switch (BTF_INFO_KIND(t->info)) {
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		prefix = BTF_INFO_KIND(t->info) == BTF_KIND_STRUCT ?
			 "struct" : "union";
		 
		if (!(kinds & (BTF_KIND_BIT(BTF_KIND_ARRAY))))
			parens = "{";
		break;
	case BTF_KIND_ENUM:
		prefix = "enum";
		break;
	default:
		break;
	}

	 
	if (kinds & BTF_KIND_BIT(BTF_KIND_PTR))
		parens = "";
	 
	if (kinds & BTF_KIND_BIT(BTF_KIND_TYPEDEF))
		prefix = "";

	if (!name)
		name = "";

	 
	if (show->flags & BTF_SHOW_NONAME)
		snprintf(show->state.name, sizeof(show->state.name), "%s",
			 parens);
	else
		snprintf(show->state.name, sizeof(show->state.name),
			 "%s%s%s(%s%s%s%s%s%s)%s",
			  
			 show_member ? "." : "",
			 show_member ? member : "",
			 show_member ? " = " : "",
			  
			 prefix,
			 strlen(prefix) > 0 && strlen(name) > 0 ? " " : "",
			  
			 name,
			  
			 strlen(ptr_suffix) > 0 ? " " : "", ptr_suffix,
			 array_suffix, parens);

	return show->state.name;
}

static const char *__btf_show_indent(struct btf_show *show)
{
	const char *indents = "                                ";
	const char *indent = &indents[strlen(indents)];

	if ((indent - show->state.depth) >= indents)
		return indent - show->state.depth;
	return indents;
}

static const char *btf_show_indent(struct btf_show *show)
{
	return show->flags & BTF_SHOW_COMPACT ? "" : __btf_show_indent(show);
}

static const char *btf_show_newline(struct btf_show *show)
{
	return show->flags & BTF_SHOW_COMPACT ? "" : "\n";
}

static const char *btf_show_delim(struct btf_show *show)
{
	if (show->state.depth == 0)
		return "";

	if ((show->flags & BTF_SHOW_COMPACT) && show->state.type &&
		BTF_INFO_KIND(show->state.type->info) == BTF_KIND_UNION)
		return "|";

	return ",";
}

__printf(2, 3) static void btf_show(struct btf_show *show, const char *fmt, ...)
{
	va_list args;

	if (!show->state.depth_check) {
		va_start(args, fmt);
		show->showfn(show, fmt, args);
		va_end(args);
	}
}






#define btf_show_type_value(show, fmt, value)				       \
	do {								       \
		if ((value) != 0 || (show->flags & BTF_SHOW_ZERO) ||	       \
		    show->state.depth == 0) {				       \
			btf_show(show, "%s%s" fmt "%s%s",		       \
				 btf_show_indent(show),			       \
				 btf_show_name(show),			       \
				 value, btf_show_delim(show),		       \
				 btf_show_newline(show));		       \
			if (show->state.depth > show->state.depth_to_show)     \
				show->state.depth_to_show = show->state.depth; \
		}							       \
	} while (0)

#define btf_show_type_values(show, fmt, ...)				       \
	do {								       \
		btf_show(show, "%s%s" fmt "%s%s", btf_show_indent(show),       \
			 btf_show_name(show),				       \
			 __VA_ARGS__, btf_show_delim(show),		       \
			 btf_show_newline(show));			       \
		if (show->state.depth > show->state.depth_to_show)	       \
			show->state.depth_to_show = show->state.depth;	       \
	} while (0)

 
static int btf_show_obj_size_left(struct btf_show *show, void *data)
{
	return show->obj.head + show->obj.size - data;
}

 
static bool btf_show_obj_is_safe(struct btf_show *show, void *data, int size)
{
	return data >= show->obj.data &&
	       (data + size) < (show->obj.data + BTF_SHOW_OBJ_SAFE_SIZE);
}







static void *__btf_show_obj_safe(struct btf_show *show, void *data, int size)
{
	if (btf_show_obj_is_safe(show, data, size))
		return show->obj.safe + (data - show->obj.data);
	return NULL;
}





























static void *btf_show_obj_safe(struct btf_show *show,
			       const struct btf_type *t,
			       void *data)
{
	const struct btf_type *rt;
	int size_left, size;
	void *safe = NULL;

	if (show->flags & BTF_SHOW_UNSAFE)
		return data;

	rt = btf_resolve_size(show->btf, t, &size);
	if (IS_ERR(rt)) {
		show->state.status = PTR_ERR(rt);
		return NULL;
	}

	




	if (show->state.depth == 0) {
		show->obj.size = size;
		show->obj.head = data;
	} else {
		




















		safe = __btf_show_obj_safe(show, data,
					   min(size,
					       BTF_SHOW_OBJ_BASE_TYPE_SIZE));
	}

	




	if (!safe) {
		size_left = btf_show_obj_size_left(show, data);
		if (size_left > BTF_SHOW_OBJ_SAFE_SIZE)
			size_left = BTF_SHOW_OBJ_SAFE_SIZE;
		show->state.status = copy_from_kernel_nofault(show->obj.safe,
							      data, size_left);
		if (!show->state.status) {
			show->obj.data = data;
			safe = show->obj.safe;
		}
	}

	return safe;
}





static void *btf_show_start_type(struct btf_show *show,
				 const struct btf_type *t,
				 u32 type_id, void *data)
{
	show->state.type = t;
	show->state.type_id = type_id;
	show->state.name[0] = '\0';

	return btf_show_obj_safe(show, t, data);
}

static void btf_show_end_type(struct btf_show *show)
{
	show->state.type = NULL;
	show->state.type_id = 0;
	show->state.name[0] = '\0';
}

static void *btf_show_start_aggr_type(struct btf_show *show,
				      const struct btf_type *t,
				      u32 type_id, void *data)
{
	void *safe_data = btf_show_start_type(show, t, type_id, data);

	if (!safe_data)
		return safe_data;

	btf_show(show, "%s%s%s", btf_show_indent(show),
		 btf_show_name(show),
		 btf_show_newline(show));
	show->state.depth++;
	return safe_data;
}

static void btf_show_end_aggr_type(struct btf_show *show,
				   const char *suffix)
{
	show->state.depth--;
	btf_show(show, "%s%s%s%s", btf_show_indent(show), suffix,
		 btf_show_delim(show), btf_show_newline(show));
	btf_show_end_type(show);
}

static void btf_show_start_member(struct btf_show *show,
				  const struct btf_member *m)
{
	show->state.member = m;
}

static void btf_show_start_array_member(struct btf_show *show)
{
	show->state.array_member = 1;
	btf_show_start_member(show, NULL);
}

static void btf_show_end_member(struct btf_show *show)
{
	show->state.member = NULL;
}

static void btf_show_end_array_member(struct btf_show *show)
{
	show->state.array_member = 0;
	btf_show_end_member(show);
}

static void *btf_show_start_array_type(struct btf_show *show,
				       const struct btf_type *t,
				       u32 type_id,
				       u16 array_encoding,
				       void *data)
{
	show->state.array_encoding = array_encoding;
	show->state.array_terminated = 0;
	return btf_show_start_aggr_type(show, t, type_id, data);
}

static void btf_show_end_array_type(struct btf_show *show)
{
	show->state.array_encoding = 0;
	show->state.array_terminated = 0;
	btf_show_end_aggr_type(show, "]");
}

static void *btf_show_start_struct_type(struct btf_show *show,
					const struct btf_type *t,
					u32 type_id,
					void *data)
{
	return btf_show_start_aggr_type(show, t, type_id, data);
}

static void btf_show_end_struct_type(struct btf_show *show)
{
	btf_show_end_aggr_type(show, "}");
}

__printf(2, 3) static void __btf_verifier_log(struct bpf_verifier_log *log,
					      const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

__printf(2, 3) static void btf_verifier_log(struct btf_verifier_env *env,
					    const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	va_start(args, fmt);
	bpf_verifier_vlog(log, fmt, args);
	va_end(args);
}

__printf(4, 5) static void __btf_verifier_log_type(struct btf_verifier_env *env,
						   const struct btf_type *t,
						   bool log_details,
						   const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	u8 kind = BTF_INFO_KIND(t->info);
	struct btf *btf = env->btf;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	



	if (log->level == BPF_LOG_KERNEL && !fmt)
		return;

	__btf_verifier_log(log, "[%u] %s %s%s",
			   env->log_type_id,
			   btf_kind_str[kind],
			   __btf_name_by_offset(btf, t->name_off),
			   log_details ? " " : "");

	if (log_details)
		btf_type_ops(t)->log_details(env, t);

	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

#define btf_verifier_log_type(env, t, ...) \
	__btf_verifier_log_type((env), (t), true, __VA_ARGS__)
#define btf_verifier_log_basic(env, t, ...) \
	__btf_verifier_log_type((env), (t), false, __VA_ARGS__)

__printf(4, 5)
static void btf_verifier_log_member(struct btf_verifier_env *env,
				    const struct btf_type *struct_type,
				    const struct btf_member *member,
				    const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	struct btf *btf = env->btf;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;

	if (log->level == BPF_LOG_KERNEL && !fmt)
		return;
	





	if (env->phase != CHECK_META)
		btf_verifier_log_type(env, struct_type, NULL);

	if (btf_type_kflag(struct_type))
		__btf_verifier_log(log,
				   "\t%s type_id=%u bitfield_size=%u bits_offset=%u",
				   __btf_name_by_offset(btf, member->name_off),
				   member->type,
				   BTF_MEMBER_BITFIELD_SIZE(member->offset),
				   BTF_MEMBER_BIT_OFFSET(member->offset));
	else
		__btf_verifier_log(log, "\t%s type_id=%u bits_offset=%u",
				   __btf_name_by_offset(btf, member->name_off),
				   member->type, member->offset);

	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

__printf(4, 5)
static void btf_verifier_log_vsi(struct btf_verifier_env *env,
				 const struct btf_type *datasec_type,
				 const struct btf_var_secinfo *vsi,
				 const char *fmt, ...)
{
	struct bpf_verifier_log *log = &env->log;
	va_list args;

	if (!bpf_verifier_log_needed(log))
		return;
	if (log->level == BPF_LOG_KERNEL && !fmt)
		return;
	if (env->phase != CHECK_META)
		btf_verifier_log_type(env, datasec_type, NULL);

	__btf_verifier_log(log, "\t type_id=%u offset=%u size=%u",
			   vsi->type, vsi->offset, vsi->size);
	if (fmt && *fmt) {
		__btf_verifier_log(log, " ");
		va_start(args, fmt);
		bpf_verifier_vlog(log, fmt, args);
		va_end(args);
	}

	__btf_verifier_log(log, "\n");
}

static void btf_verifier_log_hdr(struct btf_verifier_env *env,
				 u32 btf_data_size)
{
	struct bpf_verifier_log *log = &env->log;
	const struct btf *btf = env->btf;
	const struct btf_header *hdr;

	if (!bpf_verifier_log_needed(log))
		return;

	if (log->level == BPF_LOG_KERNEL)
		return;
	hdr = &btf->hdr;
	__btf_verifier_log(log, "magic: 0x%x\n", hdr->magic);
	__btf_verifier_log(log, "version: %u\n", hdr->version);
	__btf_verifier_log(log, "flags: 0x%x\n", hdr->flags);
	__btf_verifier_log(log, "hdr_len: %u\n", hdr->hdr_len);
	__btf_verifier_log(log, "type_off: %u\n", hdr->type_off);
	__btf_verifier_log(log, "type_len: %u\n", hdr->type_len);
	__btf_verifier_log(log, "str_off: %u\n", hdr->str_off);
	__btf_verifier_log(log, "str_len: %u\n", hdr->str_len);
	__btf_verifier_log(log, "btf_total_size: %u\n", btf_data_size);
}

static int btf_add_type(struct btf_verifier_env *env, struct btf_type *t)
{
	struct btf *btf = env->btf;

	if (btf->types_size == btf->nr_types) {
		 

		struct btf_type **new_types;
		u32 expand_by, new_size;

		if (btf->start_id + btf->types_size == BTF_MAX_TYPE) {
			btf_verifier_log(env, "Exceeded max num of types");
			return -E2BIG;
		}

		expand_by = max_t(u32, btf->types_size >> 2, 16);
		new_size = min_t(u32, BTF_MAX_TYPE,
				 btf->types_size + expand_by);

		new_types = kvcalloc(new_size, sizeof(*new_types),
				     GFP_KERNEL | __GFP_NOWARN);
		if (!new_types)
			return -ENOMEM;

		if (btf->nr_types == 0) {
			if (!btf->base_btf) {
				 
				new_types[0] = &btf_void;
				btf->nr_types++;
			}
		} else {
			memcpy(new_types, btf->types,
			       sizeof(*btf->types) * btf->nr_types);
		}

		kvfree(btf->types);
		btf->types = new_types;
		btf->types_size = new_size;
	}

	btf->types[btf->nr_types++] = t;

	return 0;
}

static int orbpf_btf_alloc_id(struct btf *btf)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock_bh(orbpf_btf_idr_lock_ptr);
	id = idr_alloc_cyclic(orbpf_btf_idr_ptr, btf, 1, INT_MAX, GFP_ATOMIC);
	if (id > 0)
		btf->id = id;
	spin_unlock_bh(orbpf_btf_idr_lock_ptr);
	idr_preload_end();

	if (WARN_ON_ONCE(!id))
		return -ENOSPC;

	return id > 0 ? 0 : id;
}

static void btf_free_id(struct btf *btf)
{
	unsigned long flags;

	








	spin_lock_irqsave(orbpf_btf_idr_lock_ptr, flags);
	idr_remove(orbpf_btf_idr_ptr, btf->id);
	spin_unlock_irqrestore(orbpf_btf_idr_lock_ptr, flags);
}

static void btf_free(struct btf *btf)
{
	kvfree(btf->types);
	kvfree(btf->resolved_sizes);
	kvfree(btf->resolved_ids);
	kvfree(btf->data);
	kfree(btf);
}

static void btf_free_rcu(struct rcu_head *rcu)
{
	struct btf *btf = container_of(rcu, struct btf, rcu);

	btf_free(btf);
}

void orbpf_btf_get(struct btf *btf)
{
	refcount_inc(&btf->refcnt);
}

void orbpf_btf_put(struct btf *btf)
{
	if (btf && refcount_dec_and_test(&btf->refcnt)) {
		btf_free_id(btf);
		call_rcu(&btf->rcu, btf_free_rcu);
	}
}

static int env_resolve_init(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	u32 nr_types = btf->nr_types;
	u32 *resolved_sizes = NULL;
	u32 *resolved_ids = NULL;
	u8 *visit_states = NULL;

	resolved_sizes = kvcalloc(nr_types, sizeof(*resolved_sizes),
				  GFP_KERNEL | __GFP_NOWARN);
	if (!resolved_sizes)
		goto nomem;

	resolved_ids = kvcalloc(nr_types, sizeof(*resolved_ids),
				GFP_KERNEL | __GFP_NOWARN);
	if (!resolved_ids)
		goto nomem;

	visit_states = kvcalloc(nr_types, sizeof(*visit_states),
				GFP_KERNEL | __GFP_NOWARN);
	if (!visit_states)
		goto nomem;

	btf->resolved_sizes = resolved_sizes;
	btf->resolved_ids = resolved_ids;
	env->visit_states = visit_states;

	return 0;

nomem:
	kvfree(resolved_sizes);
	kvfree(resolved_ids);
	kvfree(visit_states);
	return -ENOMEM;
}

static void btf_verifier_env_free(struct btf_verifier_env *env)
{
	kvfree(env->visit_states);
	kfree(env);
}

static bool env_type_is_resolve_sink(const struct btf_verifier_env *env,
				     const struct btf_type *next_type)
{
	switch (env->resolve_mode) {
	case RESOLVE_TBD:
		 
		return !btf_type_needs_resolve(next_type);
	case RESOLVE_PTR:
		


		return !btf_type_is_modifier(next_type) &&
			!btf_type_is_ptr(next_type);
	case RESOLVE_STRUCT_OR_ARRAY:
		


		return !btf_type_is_modifier(next_type) &&
			!btf_type_is_array(next_type) &&
			!btf_type_is_struct(next_type);
	default:
		BUG();
	}
}

static bool env_type_is_resolved(const struct btf_verifier_env *env,
				 u32 type_id)
{
	 
	if (type_id < env->btf->start_id)
		return true;

	return env->visit_states[type_id - env->btf->start_id] == RESOLVED;
}

static int env_stack_push(struct btf_verifier_env *env,
			  const struct btf_type *t, u32 type_id)
{
	const struct btf *btf = env->btf;
	struct resolve_vertex *v;

	if (env->top_stack == MAX_RESOLVE_DEPTH)
		return -E2BIG;

	if (type_id < btf->start_id
	    || env->visit_states[type_id - btf->start_id] != NOT_VISITED)
		return -EEXIST;

	env->visit_states[type_id - btf->start_id] = VISITED;

	v = &env->stack[env->top_stack++];
	v->t = t;
	v->type_id = type_id;
	v->next_member = 0;

	if (env->resolve_mode == RESOLVE_TBD) {
		if (btf_type_is_ptr(t))
			env->resolve_mode = RESOLVE_PTR;
		else if (btf_type_is_struct(t) || btf_type_is_array(t))
			env->resolve_mode = RESOLVE_STRUCT_OR_ARRAY;
	}

	return 0;
}

static void env_stack_set_next_member(struct btf_verifier_env *env,
				      u16 next_member)
{
	env->stack[env->top_stack - 1].next_member = next_member;
}

static void env_stack_pop_resolved(struct btf_verifier_env *env,
				   u32 resolved_type_id,
				   u32 resolved_size)
{
	u32 type_id = env->stack[--(env->top_stack)].type_id;
	struct btf *btf = env->btf;

	type_id -= btf->start_id;  
	btf->resolved_sizes[type_id] = resolved_size;
	btf->resolved_ids[type_id] = resolved_type_id;
	env->visit_states[type_id] = RESOLVED;
}

static const struct resolve_vertex *env_stack_peak(struct btf_verifier_env *env)
{
	return env->top_stack ? &env->stack[env->top_stack - 1] : NULL;
}





















static const struct btf_type *
__btf_resolve_size(const struct btf *btf, const struct btf_type *type,
		   u32 *type_size, const struct btf_type **elem_type,
		   u32 *elem_id, u32 *total_nelems, u32 *type_id)
{
	const struct btf_type *array_type = NULL;
	const struct btf_array *array = NULL;
	u32 i, size, nelems = 1, id = 0;

	for (i = 0; i < MAX_RESOLVE_DEPTH; i++) {
		switch (BTF_INFO_KIND(type->info)) {
		 
		case BTF_KIND_INT:
		case BTF_KIND_STRUCT:
		case BTF_KIND_UNION:
		case BTF_KIND_ENUM:
		case BTF_KIND_FLOAT:
			size = type->size;
			goto resolved;

		case BTF_KIND_PTR:
			size = sizeof(void *);
			goto resolved;

		 
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
			id = type->type;
			type = btf_type_by_id(btf, type->type);
			break;

		case BTF_KIND_ARRAY:
			if (!array_type)
				array_type = type;
			array = btf_type_array(type);
			if (nelems && array->nelems > U32_MAX / nelems)
				return ERR_PTR(-EINVAL);
			nelems *= array->nelems;
			type = btf_type_by_id(btf, array->type);
			break;

		 
		default:
			return ERR_PTR(-EINVAL);
		}
	}

	return ERR_PTR(-EINVAL);

resolved:
	if (nelems && size > U32_MAX / nelems)
		return ERR_PTR(-EINVAL);

	*type_size = nelems * size;
	if (total_nelems)
		*total_nelems = nelems;
	if (elem_type)
		*elem_type = type;
	if (elem_id)
		*elem_id = array ? array->type : 0;
	if (type_id && id)
		*type_id = id;

	return array_type ? : type;
}

const struct btf_type *
btf_resolve_size(const struct btf *btf, const struct btf_type *type,
		 u32 *type_size)
{
	return __btf_resolve_size(btf, type, type_size, NULL, NULL, NULL, NULL);
}

static u32 btf_resolved_type_id(const struct btf *btf, u32 type_id)
{
	while (type_id < btf->start_id)
		btf = btf->base_btf;

	return btf->resolved_ids[type_id - btf->start_id];
}

 
static const struct btf_type *btf_type_id_resolve(const struct btf *btf,
						  u32 *type_id)
{
	*type_id = btf_resolved_type_id(btf, *type_id);
	return btf_type_by_id(btf, *type_id);
}

static u32 btf_resolved_type_size(const struct btf *btf, u32 type_id)
{
	while (type_id < btf->start_id)
		btf = btf->base_btf;

	return btf->resolved_sizes[type_id - btf->start_id];
}

const struct btf_type *btf_type_id_size(const struct btf *btf,
					u32 *type_id, u32 *ret_size)
{
	const struct btf_type *size_type;
	u32 size_type_id = *type_id;
	u32 size = 0;

	size_type = btf_type_by_id(btf, size_type_id);
	if (btf_type_nosize_or_null(size_type))
		return NULL;

	if (btf_type_has_size(size_type)) {
		size = size_type->size;
	} else if (btf_type_is_array(size_type)) {
		size = btf_resolved_type_size(btf, size_type_id);
	} else if (btf_type_is_ptr(size_type)) {
		size = sizeof(void *);
	} else {
		if (WARN_ON_ONCE(!btf_type_is_modifier(size_type) &&
				 !btf_type_is_var(size_type)))
			return NULL;

		size_type_id = btf_resolved_type_id(btf, size_type_id);
		size_type = btf_type_by_id(btf, size_type_id);
		if (btf_type_nosize_or_null(size_type))
			return NULL;
		else if (btf_type_has_size(size_type))
			size = size_type->size;
		else if (btf_type_is_array(size_type))
			size = btf_resolved_type_size(btf, size_type_id);
		else if (btf_type_is_ptr(size_type))
			size = sizeof(void *);
		else
			return NULL;
	}

	*type_id = size_type_id;
	if (ret_size)
		*ret_size = size;

	return size_type;
}

static int btf_df_check_member(struct btf_verifier_env *env,
			       const struct btf_type *struct_type,
			       const struct btf_member *member,
			       const struct btf_type *member_type)
{
	btf_verifier_log_basic(env, struct_type,
			       "Unsupported check_member");
	return -EINVAL;
}

static int btf_df_check_kflag_member(struct btf_verifier_env *env,
				     const struct btf_type *struct_type,
				     const struct btf_member *member,
				     const struct btf_type *member_type)
{
	btf_verifier_log_basic(env, struct_type,
			       "Unsupported check_kflag_member");
	return -EINVAL;
}




static int btf_generic_check_kflag_member(struct btf_verifier_env *env,
					  const struct btf_type *struct_type,
					  const struct btf_member *member,
					  const struct btf_type *member_type)
{
	if (BTF_MEMBER_BITFIELD_SIZE(member->offset)) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member bitfield_size");
		return -EINVAL;
	}

	


	return btf_type_ops(member_type)->check_member(env, struct_type,
						       member,
						       member_type);
}

static int btf_df_resolve(struct btf_verifier_env *env,
			  const struct resolve_vertex *v)
{
	btf_verifier_log_basic(env, v->t, "Unsupported resolve");
	return -EINVAL;
}

static void btf_df_show(const struct btf *btf, const struct btf_type *t,
			u32 type_id, void *data, u8 bits_offsets,
			struct btf_show *show)
{
	btf_show(show, "<unsupported kind:%u>", BTF_INFO_KIND(t->info));
}

static int btf_int_check_member(struct btf_verifier_env *env,
				const struct btf_type *struct_type,
				const struct btf_member *member,
				const struct btf_type *member_type)
{
	u32 int_data = btf_type_int(member_type);
	u32 struct_bits_off = member->offset;
	u32 struct_size = struct_type->size;
	u32 nr_copy_bits;
	u32 bytes_offset;

	if (U32_MAX - struct_bits_off < BTF_INT_OFFSET(int_data)) {
		btf_verifier_log_member(env, struct_type, member,
					"bits_offset exceeds U32_MAX");
		return -EINVAL;
	}

	struct_bits_off += BTF_INT_OFFSET(int_data);
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	nr_copy_bits = BTF_INT_BITS(int_data) +
		BITS_PER_BYTE_MASKED(struct_bits_off);

	if (nr_copy_bits > BITS_PER_U128) {
		btf_verifier_log_member(env, struct_type, member,
					"nr_copy_bits exceeds 128");
		return -EINVAL;
	}

	if (struct_size < bytes_offset ||
	    struct_size - bytes_offset < BITS_ROUNDUP_BYTES(nr_copy_bits)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_int_check_kflag_member(struct btf_verifier_env *env,
				      const struct btf_type *struct_type,
				      const struct btf_member *member,
				      const struct btf_type *member_type)
{
	u32 struct_bits_off, nr_bits, nr_int_data_bits, bytes_offset;
	u32 int_data = btf_type_int(member_type);
	u32 struct_size = struct_type->size;
	u32 nr_copy_bits;

	 
	if (!btf_type_int_is_regular(member_type)) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member base type");
		return -EINVAL;
	}

	 
	nr_bits = BTF_MEMBER_BITFIELD_SIZE(member->offset);
	struct_bits_off = BTF_MEMBER_BIT_OFFSET(member->offset);
	nr_int_data_bits = BTF_INT_BITS(int_data);
	if (!nr_bits) {
		


		if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
			btf_verifier_log_member(env, struct_type, member,
						"Invalid member offset");
			return -EINVAL;
		}

		nr_bits = nr_int_data_bits;
	} else if (nr_bits > nr_int_data_bits) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member bitfield_size");
		return -EINVAL;
	}

	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	nr_copy_bits = nr_bits + BITS_PER_BYTE_MASKED(struct_bits_off);
	if (nr_copy_bits > BITS_PER_U128) {
		btf_verifier_log_member(env, struct_type, member,
					"nr_copy_bits exceeds 128");
		return -EINVAL;
	}

	if (struct_size < bytes_offset ||
	    struct_size - bytes_offset < BITS_ROUNDUP_BYTES(nr_copy_bits)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_int_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	u32 int_data, nr_bits, meta_needed = sizeof(int_data);
	u16 encoding;

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	int_data = btf_type_int(t);
	if (int_data & ~BTF_INT_MASK) {
		btf_verifier_log_basic(env, t, "Invalid int_data:%x",
				       int_data);
		return -EINVAL;
	}

	nr_bits = BTF_INT_BITS(int_data) + BTF_INT_OFFSET(int_data);

	if (nr_bits > BITS_PER_U128) {
		btf_verifier_log_type(env, t, "nr_bits exceeds %zu",
				      BITS_PER_U128);
		return -EINVAL;
	}

	if (BITS_ROUNDUP_BYTES(nr_bits) > t->size) {
		btf_verifier_log_type(env, t, "nr_bits exceeds type_size");
		return -EINVAL;
	}

	





	encoding = BTF_INT_ENCODING(int_data);
	if (encoding &&
	    encoding != BTF_INT_SIGNED &&
	    encoding != BTF_INT_CHAR &&
	    encoding != BTF_INT_BOOL) {
		btf_verifier_log_type(env, t, "Unsupported encoding");
		return -ENOTSUPP;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_int_log(struct btf_verifier_env *env,
			const struct btf_type *t)
{
	int int_data = btf_type_int(t);

	btf_verifier_log(env,
			 "size=%u bits_offset=%u nr_bits=%u encoding=%s",
			 t->size, BTF_INT_OFFSET(int_data),
			 BTF_INT_BITS(int_data),
			 btf_int_encoding_str(BTF_INT_ENCODING(int_data)));
}

static void btf_int128_print(struct btf_show *show, void *data)
{
	






	u64 upper_num, lower_num;

#ifdef __BIG_ENDIAN_BITFIELD
	upper_num = *(u64 *)data;
	lower_num = *(u64 *)(data + 8);
#else
	upper_num = *(u64 *)(data + 8);
	lower_num = *(u64 *)data;
#endif
	if (upper_num == 0)
		btf_show_type_value(show, "0x%llx", lower_num);
	else
		btf_show_type_values(show, "0x%llx%016llx", upper_num,
				     lower_num);
}

static void btf_int128_shift(u64 *print_num, u16 left_shift_bits,
			     u16 right_shift_bits)
{
	u64 upper_num, lower_num;

#ifdef __BIG_ENDIAN_BITFIELD
	upper_num = print_num[0];
	lower_num = print_num[1];
#else
	upper_num = print_num[1];
	lower_num = print_num[0];
#endif

	 
	if (left_shift_bits >= 64) {
		upper_num = lower_num << (left_shift_bits - 64);
		lower_num = 0;
	} else {
		upper_num = (upper_num << left_shift_bits) |
			    (lower_num >> (64 - left_shift_bits));
		lower_num = lower_num << left_shift_bits;
	}

	if (right_shift_bits >= 64) {
		lower_num = upper_num >> (right_shift_bits - 64);
		upper_num = 0;
	} else {
		lower_num = (lower_num >> right_shift_bits) |
			    (upper_num << (64 - right_shift_bits));
		upper_num = upper_num >> right_shift_bits;
	}

#ifdef __BIG_ENDIAN_BITFIELD
	print_num[0] = upper_num;
	print_num[1] = lower_num;
#else
	print_num[0] = lower_num;
	print_num[1] = upper_num;
#endif
}

static void btf_bitfield_show(void *data, u8 bits_offset,
			      u8 nr_bits, struct btf_show *show)
{
	u16 left_shift_bits, right_shift_bits;
	u8 nr_copy_bytes;
	u8 nr_copy_bits;
	u64 print_num[2] = {};

	nr_copy_bits = nr_bits + bits_offset;
	nr_copy_bytes = BITS_ROUNDUP_BYTES(nr_copy_bits);

	memcpy(print_num, data, nr_copy_bytes);

#ifdef __BIG_ENDIAN_BITFIELD
	left_shift_bits = bits_offset;
#else
	left_shift_bits = BITS_PER_U128 - nr_copy_bits;
#endif
	right_shift_bits = BITS_PER_U128 - nr_bits;

	btf_int128_shift(print_num, left_shift_bits, right_shift_bits);
	btf_int128_print(show, print_num);
}


static void btf_int_bits_show(const struct btf *btf,
			      const struct btf_type *t,
			      void *data, u8 bits_offset,
			      struct btf_show *show)
{
	u32 int_data = btf_type_int(t);
	u8 nr_bits = BTF_INT_BITS(int_data);
	u8 total_bits_offset;

	



	total_bits_offset = bits_offset + BTF_INT_OFFSET(int_data);
	data += BITS_ROUNDDOWN_BYTES(total_bits_offset);
	bits_offset = BITS_PER_BYTE_MASKED(total_bits_offset);
	btf_bitfield_show(data, bits_offset, nr_bits, show);
}

static void btf_int_show(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offset,
			 struct btf_show *show)
{
	u32 int_data = btf_type_int(t);
	u8 encoding = BTF_INT_ENCODING(int_data);
	bool sign = encoding & BTF_INT_SIGNED;
	u8 nr_bits = BTF_INT_BITS(int_data);
	void *safe_data;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	if (bits_offset || BTF_INT_OFFSET(int_data) ||
	    BITS_PER_BYTE_MASKED(nr_bits)) {
		btf_int_bits_show(btf, t, safe_data, bits_offset, show);
		goto out;
	}

	switch (nr_bits) {
	case 128:
		btf_int128_print(show, safe_data);
		break;
	case 64:
		if (sign)
			btf_show_type_value(show, "%lld", *(s64 *)safe_data);
		else
			btf_show_type_value(show, "%llu", *(u64 *)safe_data);
		break;
	case 32:
		if (sign)
			btf_show_type_value(show, "%d", *(s32 *)safe_data);
		else
			btf_show_type_value(show, "%u", *(u32 *)safe_data);
		break;
	case 16:
		if (sign)
			btf_show_type_value(show, "%d", *(s16 *)safe_data);
		else
			btf_show_type_value(show, "%u", *(u16 *)safe_data);
		break;
	case 8:
		if (show->state.array_encoding == BTF_INT_CHAR) {
			 
			if (show->state.array_terminated)
				break;
			if (*(char *)data == '\0') {
				show->state.array_terminated = 1;
				break;
			}
			if (isprint(*(char *)data)) {
				btf_show_type_value(show, "'%c'",
						    *(char *)safe_data);
				break;
			}
		}
		if (sign)
			btf_show_type_value(show, "%d", *(s8 *)safe_data);
		else
			btf_show_type_value(show, "%u", *(u8 *)safe_data);
		break;
	default:
		btf_int_bits_show(btf, t, safe_data, bits_offset, show);
		break;
	}
out:
	btf_show_end_type(show);
}

static const struct btf_kind_operations int_ops = {
	.check_meta = btf_int_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_int_check_member,
	.check_kflag_member = btf_int_check_kflag_member,
	.log_details = btf_int_log,
	.show = btf_int_show,
};

static int btf_modifier_check_member(struct btf_verifier_env *env,
				     const struct btf_type *struct_type,
				     const struct btf_member *member,
				     const struct btf_type *member_type)
{
	const struct btf_type *resolved_type;
	u32 resolved_type_id = member->type;
	struct btf_member resolved_member;
	struct btf *btf = env->btf;

	resolved_type = btf_type_id_size(btf, &resolved_type_id, NULL);
	if (!resolved_type) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member");
		return -EINVAL;
	}

	resolved_member = *member;
	resolved_member.type = resolved_type_id;

	return btf_type_ops(resolved_type)->check_member(env, struct_type,
							 &resolved_member,
							 resolved_type);
}

static int btf_modifier_check_kflag_member(struct btf_verifier_env *env,
					   const struct btf_type *struct_type,
					   const struct btf_member *member,
					   const struct btf_type *member_type)
{
	const struct btf_type *resolved_type;
	u32 resolved_type_id = member->type;
	struct btf_member resolved_member;
	struct btf *btf = env->btf;

	resolved_type = btf_type_id_size(btf, &resolved_type_id, NULL);
	if (!resolved_type) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member");
		return -EINVAL;
	}

	resolved_member = *member;
	resolved_member.type = resolved_type_id;

	return btf_type_ops(resolved_type)->check_kflag_member(env, struct_type,
							       &resolved_member,
							       resolved_type);
}

static int btf_ptr_check_member(struct btf_verifier_env *env,
				const struct btf_type *struct_type,
				const struct btf_member *member,
				const struct btf_type *member_type)
{
	u32 struct_size, struct_bits_off, bytes_offset;

	struct_size = struct_type->size;
	struct_bits_off = member->offset;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	if (struct_size - bytes_offset < sizeof(void *)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_ref_type_check_meta(struct btf_verifier_env *env,
				   const struct btf_type *t,
				   u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (!BTF_TYPE_ID_VALID(t->type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	


	if (BTF_INFO_KIND(t->info) == BTF_KIND_TYPEDEF) {
		if (!t->name_off ||
		    !btf_name_valid_identifier(env->btf, t->name_off)) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}
	} else {
		if (t->name_off) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static int btf_modifier_resolve(struct btf_verifier_env *env,
				const struct resolve_vertex *v)
{
	const struct btf_type *t = v->t;
	const struct btf_type *next_type;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || btf_type_is_resolve_source_only(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	





	if (!btf_type_id_size(btf, &next_type_id, NULL)) {
		if (env_type_is_resolved(env, next_type_id))
			next_type = btf_type_id_resolve(btf, &next_type_id);

		 
		if (!btf_type_is_void(next_type) &&
		    !btf_type_is_fwd(next_type) &&
		    !btf_type_is_func_proto(next_type)) {
			btf_verifier_log_type(env, v->t, "Invalid type_id");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static int btf_var_resolve(struct btf_verifier_env *env,
			   const struct resolve_vertex *v)
{
	const struct btf_type *next_type;
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || btf_type_is_resolve_source_only(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	if (btf_type_is_modifier(next_type)) {
		const struct btf_type *resolved_type;
		u32 resolved_type_id;

		resolved_type_id = next_type_id;
		resolved_type = btf_type_id_resolve(btf, &resolved_type_id);

		if (btf_type_is_ptr(resolved_type) &&
		    !env_type_is_resolve_sink(env, resolved_type) &&
		    !env_type_is_resolved(env, resolved_type_id))
			return env_stack_push(env, resolved_type,
					      resolved_type_id);
	}

	



	if (!btf_type_id_size(btf, &next_type_id, NULL)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static int btf_ptr_resolve(struct btf_verifier_env *env,
			   const struct resolve_vertex *v)
{
	const struct btf_type *next_type;
	const struct btf_type *t = v->t;
	u32 next_type_id = t->type;
	struct btf *btf = env->btf;

	next_type = btf_type_by_id(btf, next_type_id);
	if (!next_type || btf_type_is_resolve_source_only(next_type)) {
		btf_verifier_log_type(env, v->t, "Invalid type_id");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, next_type) &&
	    !env_type_is_resolved(env, next_type_id))
		return env_stack_push(env, next_type, next_type_id);

	







	if (btf_type_is_modifier(next_type)) {
		const struct btf_type *resolved_type;
		u32 resolved_type_id;

		resolved_type_id = next_type_id;
		resolved_type = btf_type_id_resolve(btf, &resolved_type_id);

		if (btf_type_is_ptr(resolved_type) &&
		    !env_type_is_resolve_sink(env, resolved_type) &&
		    !env_type_is_resolved(env, resolved_type_id))
			return env_stack_push(env, resolved_type,
					      resolved_type_id);
	}

	if (!btf_type_id_size(btf, &next_type_id, NULL)) {
		if (env_type_is_resolved(env, next_type_id))
			next_type = btf_type_id_resolve(btf, &next_type_id);

		if (!btf_type_is_void(next_type) &&
		    !btf_type_is_fwd(next_type) &&
		    !btf_type_is_func_proto(next_type)) {
			btf_verifier_log_type(env, v->t, "Invalid type_id");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, next_type_id, 0);

	return 0;
}

static void btf_modifier_show(const struct btf *btf,
			      const struct btf_type *t,
			      u32 type_id, void *data,
			      u8 bits_offset, struct btf_show *show)
{
	if (btf->resolved_ids)
		t = btf_type_id_resolve(btf, &type_id);
	else
		t = btf_type_skip_modifiers(btf, type_id, NULL);

	btf_type_ops(t)->show(btf, t, type_id, data, bits_offset, show);
}

static void btf_var_show(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offset,
			 struct btf_show *show)
{
	t = btf_type_id_resolve(btf, &type_id);

	btf_type_ops(t)->show(btf, t, type_id, data, bits_offset, show);
}

static void btf_ptr_show(const struct btf *btf, const struct btf_type *t,
			 u32 type_id, void *data, u8 bits_offset,
			 struct btf_show *show)
{
	void *safe_data;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	 
	if (show->flags & BTF_SHOW_PTR_RAW)
		btf_show_type_value(show, "0x%px", *(void **)safe_data);
	else
		btf_show_type_value(show, "0x%p", *(void **)safe_data);
	btf_show_end_type(show);
}

static void btf_ref_type_log(struct btf_verifier_env *env,
			     const struct btf_type *t)
{
	btf_verifier_log(env, "type_id=%u", t->type);
}

static struct btf_kind_operations modifier_ops = {
	.check_meta = btf_ref_type_check_meta,
	.resolve = btf_modifier_resolve,
	.check_member = btf_modifier_check_member,
	.check_kflag_member = btf_modifier_check_kflag_member,
	.log_details = btf_ref_type_log,
	.show = btf_modifier_show,
};

static struct btf_kind_operations ptr_ops = {
	.check_meta = btf_ref_type_check_meta,
	.resolve = btf_ptr_resolve,
	.check_member = btf_ptr_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_ref_type_log,
	.show = btf_ptr_show,
};

static s32 btf_fwd_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (t->type) {
		btf_verifier_log_type(env, t, "type != 0");
		return -EINVAL;
	}

	 
	if (!t->name_off ||
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static void btf_fwd_type_log(struct btf_verifier_env *env,
			     const struct btf_type *t)
{
	btf_verifier_log(env, "%s", btf_type_kflag(t) ? "union" : "struct");
}

static struct btf_kind_operations fwd_ops = {
	.check_meta = btf_fwd_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_fwd_type_log,
	.show = btf_df_show,
};

static int btf_array_check_member(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;
	u32 array_type_id, array_size;
	struct btf *btf = env->btf;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	array_type_id = member->type;
	btf_type_id_size(btf, &array_type_id, &array_size);
	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < array_size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_array_check_meta(struct btf_verifier_env *env,
				const struct btf_type *t,
				u32 meta_left)
{
	const struct btf_array *array = btf_type_array(t);
	u32 meta_needed = sizeof(*array);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	 
	if (t->name_off) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (t->size) {
		btf_verifier_log_type(env, t, "size != 0");
		return -EINVAL;
	}

	


	if (!array->type || !BTF_TYPE_ID_VALID(array->type)) {
		btf_verifier_log_type(env, t, "Invalid elem");
		return -EINVAL;
	}

	if (!array->index_type || !BTF_TYPE_ID_VALID(array->index_type)) {
		btf_verifier_log_type(env, t, "Invalid index");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static int btf_array_resolve(struct btf_verifier_env *env,
			     const struct resolve_vertex *v)
{
	const struct btf_array *array = btf_type_array(v->t);
	const struct btf_type *elem_type, *index_type;
	u32 elem_type_id, index_type_id;
	struct btf *btf = env->btf;
	u32 elem_size;

	 
	index_type_id = array->index_type;
	index_type = btf_type_by_id(btf, index_type_id);
	if (btf_type_nosize_or_null(index_type) ||
	    btf_type_is_resolve_source_only(index_type)) {
		btf_verifier_log_type(env, v->t, "Invalid index");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, index_type) &&
	    !env_type_is_resolved(env, index_type_id))
		return env_stack_push(env, index_type, index_type_id);

	index_type = btf_type_id_size(btf, &index_type_id, NULL);
	if (!index_type || !btf_type_is_int(index_type) ||
	    !btf_type_int_is_regular(index_type)) {
		btf_verifier_log_type(env, v->t, "Invalid index");
		return -EINVAL;
	}

	 
	elem_type_id = array->type;
	elem_type = btf_type_by_id(btf, elem_type_id);
	if (btf_type_nosize_or_null(elem_type) ||
	    btf_type_is_resolve_source_only(elem_type)) {
		btf_verifier_log_type(env, v->t,
				      "Invalid elem");
		return -EINVAL;
	}

	if (!env_type_is_resolve_sink(env, elem_type) &&
	    !env_type_is_resolved(env, elem_type_id))
		return env_stack_push(env, elem_type, elem_type_id);

	elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
	if (!elem_type) {
		btf_verifier_log_type(env, v->t, "Invalid elem");
		return -EINVAL;
	}

	if (btf_type_is_int(elem_type) && !btf_type_int_is_regular(elem_type)) {
		btf_verifier_log_type(env, v->t, "Invalid array of int");
		return -EINVAL;
	}

	if (array->nelems && elem_size > U32_MAX / array->nelems) {
		btf_verifier_log_type(env, v->t,
				      "Array size overflows U32_MAX");
		return -EINVAL;
	}

	env_stack_pop_resolved(env, elem_type_id, elem_size * array->nelems);

	return 0;
}

static void btf_array_log(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	const struct btf_array *array = btf_type_array(t);

	btf_verifier_log(env, "type_id=%u index_type_id=%u nr_elems=%u",
			 array->type, array->index_type, array->nelems);
}

static void __btf_array_show(const struct btf *btf, const struct btf_type *t,
			     u32 type_id, void *data, u8 bits_offset,
			     struct btf_show *show)
{
	const struct btf_array *array = btf_type_array(t);
	const struct btf_kind_operations *elem_ops;
	const struct btf_type *elem_type;
	u32 i, elem_size = 0, elem_type_id;
	u16 encoding = 0;

	elem_type_id = array->type;
	elem_type = btf_type_skip_modifiers(btf, elem_type_id, NULL);
	if (elem_type && btf_type_has_size(elem_type))
		elem_size = elem_type->size;

	if (elem_type && btf_type_is_int(elem_type)) {
		u32 int_type = btf_type_int(elem_type);

		encoding = BTF_INT_ENCODING(int_type);

		




		if (elem_size == 1)
			encoding = BTF_INT_CHAR;
	}

	if (!btf_show_start_array_type(show, t, type_id, encoding, data))
		return;

	if (!elem_type)
		goto out;
	elem_ops = btf_type_ops(elem_type);

	for (i = 0; i < array->nelems; i++) {

		btf_show_start_array_member(show);

		elem_ops->show(btf, elem_type, elem_type_id, data,
			       bits_offset, show);
		data += elem_size;

		btf_show_end_array_member(show);

		if (show->state.array_terminated)
			break;
	}
out:
	btf_show_end_array_type(show);
}

static void btf_array_show(const struct btf *btf, const struct btf_type *t,
			   u32 type_id, void *data, u8 bits_offset,
			   struct btf_show *show)
{
	const struct btf_member *m = show->state.member;

	




	if (show->state.depth > 0 && !(show->flags & BTF_SHOW_ZERO)) {
		if (!show->state.depth_check) {
			show->state.depth_check = show->state.depth + 1;
			show->state.depth_to_show = 0;
		}
		__btf_array_show(btf, t, type_id, data, bits_offset, show);
		show->state.member = m;

		if (show->state.depth_check != show->state.depth + 1)
			return;
		show->state.depth_check = 0;

		if (show->state.depth_to_show <= show->state.depth)
			return;
		



	}
	__btf_array_show(btf, t, type_id, data, bits_offset, show);
}

static struct btf_kind_operations array_ops = {
	.check_meta = btf_array_check_meta,
	.resolve = btf_array_resolve,
	.check_member = btf_array_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_array_log,
	.show = btf_array_show,
};

static int btf_struct_check_member(struct btf_verifier_env *env,
				   const struct btf_type *struct_type,
				   const struct btf_member *member,
				   const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < member_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_struct_check_meta(struct btf_verifier_env *env,
				 const struct btf_type *t,
				 u32 meta_left)
{
	bool is_union = BTF_INFO_KIND(t->info) == BTF_KIND_UNION;
	const struct btf_member *member;
	u32 meta_needed, last_offset;
	struct btf *btf = env->btf;
	u32 struct_size = t->size;
	u32 offset;
	u16 i;

	meta_needed = btf_type_vlen(t) * sizeof(*member);
	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	 
	if (t->name_off &&
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	last_offset = 0;
	for_each_member(i, t, member) {
		if (!btf_name_offset_valid(btf, member->name_off)) {
			btf_verifier_log_member(env, t, member,
						"Invalid member name_offset:%u",
						member->name_off);
			return -EINVAL;
		}

		 
		if (member->name_off &&
		    !btf_name_valid_identifier(btf, member->name_off)) {
			btf_verifier_log_member(env, t, member, "Invalid name");
			return -EINVAL;
		}
		 
		if (!member->type || !BTF_TYPE_ID_VALID(member->type)) {
			btf_verifier_log_member(env, t, member,
						"Invalid type_id");
			return -EINVAL;
		}

		offset = orbpf_btf_member_bit_offset(t, member);
		if (is_union && offset) {
			btf_verifier_log_member(env, t, member,
						"Invalid member bits_offset");
			return -EINVAL;
		}

		



		if (last_offset > offset) {
			btf_verifier_log_member(env, t, member,
						"Invalid member bits_offset");
			return -EINVAL;
		}

		if (BITS_ROUNDUP_BYTES(offset) > struct_size) {
			btf_verifier_log_member(env, t, member,
						"Member bits_offset exceeds its struct size");
			return -EINVAL;
		}

		btf_verifier_log_member(env, t, member, NULL);
		last_offset = offset;
	}

	return meta_needed;
}

static int btf_struct_resolve(struct btf_verifier_env *env,
			      const struct resolve_vertex *v)
{
	const struct btf_member *member;
	int err;
	u16 i;

	



	if (v->next_member) {
		const struct btf_type *last_member_type;
		const struct btf_member *last_member;
		u16 last_member_type_id;

		last_member = btf_type_member(v->t) + v->next_member - 1;
		last_member_type_id = last_member->type;
		if (WARN_ON_ONCE(!env_type_is_resolved(env,
						       last_member_type_id)))
			return -EINVAL;

		last_member_type = btf_type_by_id(env->btf,
						  last_member_type_id);
		if (btf_type_kflag(v->t))
			err = btf_type_ops(last_member_type)->check_kflag_member(env, v->t,
								last_member,
								last_member_type);
		else
			err = btf_type_ops(last_member_type)->check_member(env, v->t,
								last_member,
								last_member_type);
		if (err)
			return err;
	}

	for_each_member_from(i, v->next_member, v->t, member) {
		u32 member_type_id = member->type;
		const struct btf_type *member_type = btf_type_by_id(env->btf,
								member_type_id);

		if (btf_type_nosize_or_null(member_type) ||
		    btf_type_is_resolve_source_only(member_type)) {
			btf_verifier_log_member(env, v->t, member,
						"Invalid member");
			return -EINVAL;
		}

		if (!env_type_is_resolve_sink(env, member_type) &&
		    !env_type_is_resolved(env, member_type_id)) {
			env_stack_set_next_member(env, i + 1);
			return env_stack_push(env, member_type, member_type_id);
		}

		if (btf_type_kflag(v->t))
			err = btf_type_ops(member_type)->check_kflag_member(env, v->t,
									    member,
									    member_type);
		else
			err = btf_type_ops(member_type)->check_member(env, v->t,
								      member,
								      member_type);
		if (err)
			return err;
	}

	env_stack_pop_resolved(env, 0, 0);

	return 0;
}

static void btf_struct_log(struct btf_verifier_env *env,
			   const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}





int btf_find_spin_lock(const struct btf *btf, const struct btf_type *t)
{
	const struct btf_member *member;
	u32 i, off = -ENOENT;

	if (!__btf_type_is_struct(t))
		return -EINVAL;

	for_each_member(i, t, member) {
		const struct btf_type *member_type = btf_type_by_id(btf,
								    member->type);
		if (!__btf_type_is_struct(member_type))
			continue;
		if (member_type->size != sizeof(struct bpf_spin_lock))
			continue;
		if (strcmp(__btf_name_by_offset(btf, member_type->name_off),
			   "bpf_spin_lock"))
			continue;
		if (off != -ENOENT)
			 
			return -E2BIG;
		off = orbpf_btf_member_bit_offset(t, member);
		if (off % 8)
			 
			return -EINVAL;
		off /= 8;
		if (off % __alignof__(struct bpf_spin_lock))
			 
			return -EINVAL;
	}
	return off;
}

static void __btf_struct_show(const struct btf *btf, const struct btf_type *t,
			      u32 type_id, void *data, u8 bits_offset,
			      struct btf_show *show)
{
	const struct btf_member *member;
	void *safe_data;
	u32 i;

	safe_data = btf_show_start_struct_type(show, t, type_id, data);
	if (!safe_data)
		return;

	for_each_member(i, t, member) {
		const struct btf_type *member_type = btf_type_by_id(btf,
								member->type);
		const struct btf_kind_operations *ops;
		u32 member_offset, bitfield_size;
		u32 bytes_offset;
		u8 bits8_offset;

		btf_show_start_member(show, member);

		member_offset = orbpf_btf_member_bit_offset(t, member);
		bitfield_size = orbpf_btf_member_bitfield_size(t, member);
		bytes_offset = BITS_ROUNDDOWN_BYTES(member_offset);
		bits8_offset = BITS_PER_BYTE_MASKED(member_offset);
		if (bitfield_size) {
			safe_data = btf_show_start_type(show, member_type,
							member->type,
							data + bytes_offset);
			if (safe_data)
				btf_bitfield_show(safe_data,
						  bits8_offset,
						  bitfield_size, show);
			btf_show_end_type(show);
		} else {
			ops = btf_type_ops(member_type);
			ops->show(btf, member_type, member->type,
				  data + bytes_offset, bits8_offset, show);
		}

		btf_show_end_member(show);
	}

	btf_show_end_struct_type(show);
}

static void btf_struct_show(const struct btf *btf, const struct btf_type *t,
			    u32 type_id, void *data, u8 bits_offset,
			    struct btf_show *show)
{
	const struct btf_member *m = show->state.member;

	




	if (show->state.depth > 0 && !(show->flags & BTF_SHOW_ZERO)) {
		if (!show->state.depth_check) {
			show->state.depth_check = show->state.depth + 1;
			show->state.depth_to_show = 0;
		}
		__btf_struct_show(btf, t, type_id, data, bits_offset, show);
		 
		show->state.member = m;
		if (show->state.depth_check != show->state.depth + 1)
			return;
		show->state.depth_check = 0;

		if (show->state.depth_to_show <= show->state.depth)
			return;
		



	}

	__btf_struct_show(btf, t, type_id, data, bits_offset, show);
}

static struct btf_kind_operations struct_ops = {
	.check_meta = btf_struct_check_meta,
	.resolve = btf_struct_resolve,
	.check_member = btf_struct_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_struct_log,
	.show = btf_struct_show,
};

static int btf_enum_check_member(struct btf_verifier_env *env,
				 const struct btf_type *struct_type,
				 const struct btf_member *member,
				 const struct btf_type *member_type)
{
	u32 struct_bits_off = member->offset;
	u32 struct_size, bytes_offset;

	if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not byte aligned");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_offset = BITS_ROUNDDOWN_BYTES(struct_bits_off);
	if (struct_size - bytes_offset < member_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static int btf_enum_check_kflag_member(struct btf_verifier_env *env,
				       const struct btf_type *struct_type,
				       const struct btf_member *member,
				       const struct btf_type *member_type)
{
	u32 struct_bits_off, nr_bits, bytes_end, struct_size;
	u32 int_bitsize = sizeof(int) * BITS_PER_BYTE;

	struct_bits_off = BTF_MEMBER_BIT_OFFSET(member->offset);
	nr_bits = BTF_MEMBER_BITFIELD_SIZE(member->offset);
	if (!nr_bits) {
		if (BITS_PER_BYTE_MASKED(struct_bits_off)) {
			btf_verifier_log_member(env, struct_type, member,
						"Member is not byte aligned");
			return -EINVAL;
		}

		nr_bits = int_bitsize;
	} else if (nr_bits > int_bitsize) {
		btf_verifier_log_member(env, struct_type, member,
					"Invalid member bitfield_size");
		return -EINVAL;
	}

	struct_size = struct_type->size;
	bytes_end = BITS_ROUNDUP_BYTES(struct_bits_off + nr_bits);
	if (struct_size < bytes_end) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static s32 btf_enum_check_meta(struct btf_verifier_env *env,
			       const struct btf_type *t,
			       u32 meta_left)
{
	const struct btf_enum *enums = btf_type_enum(t);
	struct btf *btf = env->btf;
	u16 i, nr_enums;
	u32 meta_needed;

	nr_enums = btf_type_vlen(t);
	meta_needed = nr_enums * sizeof(*enums);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (t->size > 8 || !is_power_of_2(t->size)) {
		btf_verifier_log_type(env, t, "Unexpected size");
		return -EINVAL;
	}

	 
	if (t->name_off &&
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	for (i = 0; i < nr_enums; i++) {
		if (!btf_name_offset_valid(btf, enums[i].name_off)) {
			btf_verifier_log(env, "\tInvalid name_offset:%u",
					 enums[i].name_off);
			return -EINVAL;
		}

		 
		if (!enums[i].name_off ||
		    !btf_name_valid_identifier(btf, enums[i].name_off)) {
			btf_verifier_log_type(env, t, "Invalid name");
			return -EINVAL;
		}

		if (env->log.level == BPF_LOG_KERNEL)
			continue;
		btf_verifier_log(env, "\t%s val=%d\n",
				 __btf_name_by_offset(btf, enums[i].name_off),
				 enums[i].val);
	}

	return meta_needed;
}

static void btf_enum_log(struct btf_verifier_env *env,
			 const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}

static void btf_enum_show(const struct btf *btf, const struct btf_type *t,
			  u32 type_id, void *data, u8 bits_offset,
			  struct btf_show *show)
{
	const struct btf_enum *enums = btf_type_enum(t);
	u32 i, nr_enums = btf_type_vlen(t);
	void *safe_data;
	int v;

	safe_data = btf_show_start_type(show, t, type_id, data);
	if (!safe_data)
		return;

	v = *(int *)safe_data;

	for (i = 0; i < nr_enums; i++) {
		if (v != enums[i].val)
			continue;

		btf_show_type_value(show, "%s",
				    __btf_name_by_offset(btf,
							 enums[i].name_off));

		btf_show_end_type(show);
		return;
	}

	btf_show_type_value(show, "%d", v);
	btf_show_end_type(show);
}

static struct btf_kind_operations enum_ops = {
	.check_meta = btf_enum_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_enum_check_member,
	.check_kflag_member = btf_enum_check_kflag_member,
	.log_details = btf_enum_log,
	.show = btf_enum_show,
};

static s32 btf_func_proto_check_meta(struct btf_verifier_env *env,
				     const struct btf_type *t,
				     u32 meta_left)
{
	u32 meta_needed = btf_type_vlen(t) * sizeof(struct btf_param);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (t->name_off) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_func_proto_log(struct btf_verifier_env *env,
			       const struct btf_type *t)
{
	const struct btf_param *args = (const struct btf_param *)(t + 1);
	u16 nr_args = btf_type_vlen(t), i;

	btf_verifier_log(env, "return=%u args=(", t->type);
	if (!nr_args) {
		btf_verifier_log(env, "void");
		goto done;
	}

	if (nr_args == 1 && !args[0].type) {
		 
		btf_verifier_log(env, "vararg");
		goto done;
	}

	btf_verifier_log(env, "%u %s", args[0].type,
			 __btf_name_by_offset(env->btf,
					      args[0].name_off));
	for (i = 1; i < nr_args - 1; i++)
		btf_verifier_log(env, ", %u %s", args[i].type,
				 __btf_name_by_offset(env->btf,
						      args[i].name_off));

	if (nr_args > 1) {
		const struct btf_param *last_arg = &args[nr_args - 1];

		if (last_arg->type)
			btf_verifier_log(env, ", %u %s", last_arg->type,
					 __btf_name_by_offset(env->btf,
							      last_arg->name_off));
		else
			btf_verifier_log(env, ", vararg");
	}

done:
	btf_verifier_log(env, ")");
}

static struct btf_kind_operations func_proto_ops = {
	.check_meta = btf_func_proto_check_meta,
	.resolve = btf_df_resolve,
	








	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_func_proto_log,
	.show = btf_df_show,
};

static s32 btf_func_check_meta(struct btf_verifier_env *env,
			       const struct btf_type *t,
			       u32 meta_left)
{
	if (!t->name_off ||
	    !btf_name_valid_identifier(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	if ((btf_type_vlen(t) & 0x3) > BTF_FUNC_GLOBAL) {
		btf_verifier_log_type(env, t, "Invalid func linkage");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static struct btf_kind_operations func_ops = {
	.check_meta = btf_func_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_df_check_member,
	.check_kflag_member = btf_df_check_kflag_member,
	.log_details = btf_ref_type_log,
	.show = btf_df_show,
};

static s32 btf_var_check_meta(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 meta_left)
{
	const struct btf_var *var;
	u32 meta_needed = sizeof(*var);

	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (!t->name_off ||
	    !__btf_name_valid(env->btf, t->name_off, true)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	 
	if (!t->type || !BTF_TYPE_ID_VALID(t->type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	var = btf_type_var(t);
	if (var->linkage != BTF_VAR_STATIC &&
	    var->linkage != BTF_VAR_GLOBAL_ALLOCATED) {
		btf_verifier_log_type(env, t, "Linkage not supported");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return meta_needed;
}

static void btf_var_log(struct btf_verifier_env *env, const struct btf_type *t)
{
	const struct btf_var *var = btf_type_var(t);

	btf_verifier_log(env, "type_id=%u linkage=%u", t->type, var->linkage);
}

static const struct btf_kind_operations var_ops = {
	.check_meta		= btf_var_check_meta,
	.resolve		= btf_var_resolve,
	.check_member		= btf_df_check_member,
	.check_kflag_member	= btf_df_check_kflag_member,
	.log_details		= btf_var_log,
	.show			= btf_var_show,
};

static s32 btf_datasec_check_meta(struct btf_verifier_env *env,
				  const struct btf_type *t,
				  u32 meta_left)
{
	const struct btf_var_secinfo *vsi;
	u64 last_vsi_end_off = 0, sum = 0;
	u32 i, meta_needed;

	meta_needed = btf_type_vlen(t) * sizeof(*vsi);
	if (meta_left < meta_needed) {
		btf_verifier_log_basic(env, t,
				       "meta_left:%u meta_needed:%u",
				       meta_left, meta_needed);
		return -EINVAL;
	}

	if (!t->size) {
		btf_verifier_log_type(env, t, "size == 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (!t->name_off ||
	    !btf_name_valid_section(env->btf, t->name_off)) {
		btf_verifier_log_type(env, t, "Invalid name");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	for_each_vsi(i, t, vsi) {
		 
		if (!vsi->type || !BTF_TYPE_ID_VALID(vsi->type)) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid type_id");
			return -EINVAL;
		}

		if (vsi->offset < last_vsi_end_off || vsi->offset >= t->size) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid offset");
			return -EINVAL;
		}

		if (!vsi->size || vsi->size > t->size) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid size");
			return -EINVAL;
		}

		last_vsi_end_off = vsi->offset + vsi->size;
		if (last_vsi_end_off > t->size) {
			btf_verifier_log_vsi(env, t, vsi,
					     "Invalid offset+size");
			return -EINVAL;
		}

		btf_verifier_log_vsi(env, t, vsi, NULL);
		sum += vsi->size;
	}

	if (t->size < sum) {
		btf_verifier_log_type(env, t, "Invalid btf_info size");
		return -EINVAL;
	}

	return meta_needed;
}

static int btf_datasec_resolve(struct btf_verifier_env *env,
			       const struct resolve_vertex *v)
{
	const struct btf_var_secinfo *vsi;
	struct btf *btf = env->btf;
	u16 i;

	for_each_vsi_from(i, v->next_member, v->t, vsi) {
		u32 var_type_id = vsi->type, type_id, type_size = 0;
		const struct btf_type *var_type = btf_type_by_id(env->btf,
								 var_type_id);
		if (!var_type || !btf_type_is_var(var_type)) {
			btf_verifier_log_vsi(env, v->t, vsi,
					     "Not a VAR kind member");
			return -EINVAL;
		}

		if (!env_type_is_resolve_sink(env, var_type) &&
		    !env_type_is_resolved(env, var_type_id)) {
			env_stack_set_next_member(env, i + 1);
			return env_stack_push(env, var_type, var_type_id);
		}

		type_id = var_type->type;
		if (!btf_type_id_size(btf, &type_id, &type_size)) {
			btf_verifier_log_vsi(env, v->t, vsi, "Invalid type");
			return -EINVAL;
		}

		if (vsi->size > type_size) {
			btf_verifier_log_vsi(env, v->t, vsi, "Invalid size");
			return -EINVAL;
		}
	}

	env_stack_pop_resolved(env, 0, 0);
	return 0;
}

static void btf_datasec_log(struct btf_verifier_env *env,
			    const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u vlen=%u", t->size, btf_type_vlen(t));
}

static void btf_datasec_show(const struct btf *btf,
			     const struct btf_type *t, u32 type_id,
			     void *data, u8 bits_offset,
			     struct btf_show *show)
{
	const struct btf_var_secinfo *vsi;
	const struct btf_type *var;
	u32 i;

	if (!btf_show_start_type(show, t, type_id, data))
		return;

	btf_show_type_value(show, "section (\"%s\") = {",
			    __btf_name_by_offset(btf, t->name_off));
	for_each_vsi(i, t, vsi) {
		var = btf_type_by_id(btf, vsi->type);
		if (i)
			btf_show(show, ",");
		btf_type_ops(var)->show(btf, var, vsi->type,
					data + vsi->offset, bits_offset, show);
	}
	btf_show_end_type(show);
}

static const struct btf_kind_operations datasec_ops = {
	.check_meta		= btf_datasec_check_meta,
	.resolve		= btf_datasec_resolve,
	.check_member		= btf_df_check_member,
	.check_kflag_member	= btf_df_check_kflag_member,
	.log_details		= btf_datasec_log,
	.show			= btf_datasec_show,
};

static s32 btf_float_check_meta(struct btf_verifier_env *env,
				const struct btf_type *t,
				u32 meta_left)
{
	if (btf_type_vlen(t)) {
		btf_verifier_log_type(env, t, "vlen != 0");
		return -EINVAL;
	}

	if (btf_type_kflag(t)) {
		btf_verifier_log_type(env, t, "Invalid btf_info kind_flag");
		return -EINVAL;
	}

	if (t->size != 2 && t->size != 4 && t->size != 8 && t->size != 12 &&
	    t->size != 16) {
		btf_verifier_log_type(env, t, "Invalid type_size");
		return -EINVAL;
	}

	btf_verifier_log_type(env, t, NULL);

	return 0;
}

static int btf_float_check_member(struct btf_verifier_env *env,
				  const struct btf_type *struct_type,
				  const struct btf_member *member,
				  const struct btf_type *member_type)
{
	u64 start_offset_bytes;
	u64 end_offset_bytes;
	u64 misalign_bits;
	u64 align_bytes;
	u64 align_bits;

	



	align_bytes = min_t(u64, sizeof(void *), member_type->size);
	align_bits = align_bytes * BITS_PER_BYTE;
	div64_u64_rem(member->offset, align_bits, &misalign_bits);
	if (misalign_bits) {
		btf_verifier_log_member(env, struct_type, member,
					"Member is not properly aligned");
		return -EINVAL;
	}

	start_offset_bytes = member->offset / BITS_PER_BYTE;
	end_offset_bytes = start_offset_bytes + member_type->size;
	if (end_offset_bytes > struct_type->size) {
		btf_verifier_log_member(env, struct_type, member,
					"Member exceeds struct_size");
		return -EINVAL;
	}

	return 0;
}

static void btf_float_log(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	btf_verifier_log(env, "size=%u", t->size);
}

static const struct btf_kind_operations float_ops = {
	.check_meta = btf_float_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_float_check_member,
	.check_kflag_member = btf_generic_check_kflag_member,
	.log_details = btf_float_log,
	.show = btf_df_show,
};

static int btf_func_proto_check(struct btf_verifier_env *env,
				const struct btf_type *t)
{
	const struct btf_type *ret_type;
	const struct btf_param *args;
	const struct btf *btf;
	u16 nr_args, i;
	int err;

	btf = env->btf;
	args = (const struct btf_param *)(t + 1);
	nr_args = btf_type_vlen(t);

	 
	if (t->type) {
		u32 ret_type_id = t->type;

		ret_type = btf_type_by_id(btf, ret_type_id);
		if (!ret_type) {
			btf_verifier_log_type(env, t, "Invalid return type");
			return -EINVAL;
		}

		if (btf_type_needs_resolve(ret_type) &&
		    !env_type_is_resolved(env, ret_type_id)) {
			err = btf_resolve(env, ret_type, ret_type_id);
			if (err)
				return err;
		}

		 
		if (!btf_type_id_size(btf, &ret_type_id, NULL)) {
			btf_verifier_log_type(env, t, "Invalid return type");
			return -EINVAL;
		}
	}

	if (!nr_args)
		return 0;

	 
	if (!args[nr_args - 1].type) {
		if (args[nr_args - 1].name_off) {
			btf_verifier_log_type(env, t, "Invalid arg#%u",
					      nr_args);
			return -EINVAL;
		}
		nr_args--;
	}

	err = 0;
	for (i = 0; i < nr_args; i++) {
		const struct btf_type *arg_type;
		u32 arg_type_id;

		arg_type_id = args[i].type;
		arg_type = btf_type_by_id(btf, arg_type_id);
		if (!arg_type) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			err = -EINVAL;
			break;
		}

		if (args[i].name_off &&
		    (!btf_name_offset_valid(btf, args[i].name_off) ||
		     !btf_name_valid_identifier(btf, args[i].name_off))) {
			btf_verifier_log_type(env, t,
					      "Invalid arg#%u", i + 1);
			err = -EINVAL;
			break;
		}

		if (btf_type_needs_resolve(arg_type) &&
		    !env_type_is_resolved(env, arg_type_id)) {
			err = btf_resolve(env, arg_type, arg_type_id);
			if (err)
				break;
		}

		if (!btf_type_id_size(btf, &arg_type_id, NULL)) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			err = -EINVAL;
			break;
		}
	}

	return err;
}

static int btf_func_check(struct btf_verifier_env *env,
			  const struct btf_type *t)
{
	const struct btf_type *proto_type;
	const struct btf_param *args;
	const struct btf *btf;
	u16 nr_args, i;

	btf = env->btf;
	proto_type = btf_type_by_id(btf, t->type);

	if (!proto_type || !btf_type_is_func_proto(proto_type)) {
		btf_verifier_log_type(env, t, "Invalid type_id");
		return -EINVAL;
	}

	args = (const struct btf_param *)(proto_type + 1);
	nr_args = btf_type_vlen(proto_type);
	for (i = 0; i < nr_args; i++) {
		if (!args[i].name_off && args[i].type) {
			btf_verifier_log_type(env, t, "Invalid arg#%u", i + 1);
			return -EINVAL;
		}
	}

	return 0;
}

static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS] = {
	[BTF_KIND_INT] = &int_ops,
	[BTF_KIND_PTR] = &ptr_ops,
	[BTF_KIND_ARRAY] = &array_ops,
	[BTF_KIND_STRUCT] = &struct_ops,
	[BTF_KIND_UNION] = &struct_ops,
	[BTF_KIND_ENUM] = &enum_ops,
	[BTF_KIND_FWD] = &fwd_ops,
	[BTF_KIND_TYPEDEF] = &modifier_ops,
	[BTF_KIND_VOLATILE] = &modifier_ops,
	[BTF_KIND_CONST] = &modifier_ops,
	[BTF_KIND_RESTRICT] = &modifier_ops,
	[BTF_KIND_FUNC] = &func_ops,
	[BTF_KIND_FUNC_PROTO] = &func_proto_ops,
	[BTF_KIND_VAR] = &var_ops,
	[BTF_KIND_DATASEC] = &datasec_ops,
	[BTF_KIND_FLOAT] = &float_ops,
};

static s32 btf_check_meta(struct btf_verifier_env *env,
			  const struct btf_type *t,
			  u32 meta_left)
{
	u32 saved_meta_left = meta_left;
	s32 var_meta_size;

	if (meta_left < sizeof(*t)) {
		btf_verifier_log(env, "[%u] meta_left:%u meta_needed:%zu",
				 env->log_type_id, meta_left, sizeof(*t));
		return -EINVAL;
	}
	meta_left -= sizeof(*t);

	if (t->info & ~BTF_INFO_MASK) {
		btf_verifier_log(env, "[%u] Invalid btf_info:%x",
				 env->log_type_id, t->info);
		return -EINVAL;
	}

	if (BTF_INFO_KIND(t->info) > BTF_KIND_MAX ||
	    BTF_INFO_KIND(t->info) == BTF_KIND_UNKN) {
		btf_verifier_log(env, "[%u] Invalid kind:%u",
				 env->log_type_id, BTF_INFO_KIND(t->info));
		return -EINVAL;
	}

	if (!btf_name_offset_valid(env->btf, t->name_off)) {
		btf_verifier_log(env, "[%u] Invalid name_offset:%u",
				 env->log_type_id, t->name_off);
		return -EINVAL;
	}

	var_meta_size = btf_type_ops(t)->check_meta(env, t, meta_left);
	if (var_meta_size < 0)
		return var_meta_size;

	meta_left -= var_meta_size;

	return saved_meta_left - meta_left;
}

static int btf_check_all_metas(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	struct btf_header *hdr;
	void *cur, *end;

	hdr = &btf->hdr;
	cur = btf->nohdr_data + hdr->type_off;
	end = cur + hdr->type_len;

	env->log_type_id = btf->base_btf ? btf->start_id : 1;
	while (cur < end) {
		struct btf_type *t = cur;
		s32 meta_size;

		meta_size = btf_check_meta(env, t, end - cur);
		if (meta_size < 0)
			return meta_size;

		btf_add_type(env, t);
		cur += meta_size;
		env->log_type_id++;
	}

	return 0;
}

static bool btf_resolve_valid(struct btf_verifier_env *env,
			      const struct btf_type *t,
			      u32 type_id)
{
	struct btf *btf = env->btf;

	if (!env_type_is_resolved(env, type_id))
		return false;

	if (btf_type_is_struct(t) || btf_type_is_datasec(t))
		return !btf_resolved_type_id(btf, type_id) &&
		       !btf_resolved_type_size(btf, type_id);

	if (btf_type_is_modifier(t) || btf_type_is_ptr(t) ||
	    btf_type_is_var(t)) {
		t = btf_type_id_resolve(btf, &type_id);
		return t &&
		       !btf_type_is_modifier(t) &&
		       !btf_type_is_var(t) &&
		       !btf_type_is_datasec(t);
	}

	if (btf_type_is_array(t)) {
		const struct btf_array *array = btf_type_array(t);
		const struct btf_type *elem_type;
		u32 elem_type_id = array->type;
		u32 elem_size;

		elem_type = btf_type_id_size(btf, &elem_type_id, &elem_size);
		return elem_type && !btf_type_is_modifier(elem_type) &&
			(array->nelems * elem_size ==
			 btf_resolved_type_size(btf, type_id));
	}

	return false;
}

static int btf_resolve(struct btf_verifier_env *env,
		       const struct btf_type *t, u32 type_id)
{
	u32 save_log_type_id = env->log_type_id;
	const struct resolve_vertex *v;
	int err = 0;

	env->resolve_mode = RESOLVE_TBD;
	env_stack_push(env, t, type_id);
	while (!err && (v = env_stack_peak(env))) {
		env->log_type_id = v->type_id;
		err = btf_type_ops(v->t)->resolve(env, v);
	}

	env->log_type_id = type_id;
	if (err == -E2BIG) {
		btf_verifier_log_type(env, t,
				      "Exceeded max resolving depth:%u",
				      MAX_RESOLVE_DEPTH);
	} else if (err == -EEXIST) {
		btf_verifier_log_type(env, t, "Loop detected");
	}

	 
	if (!err && !btf_resolve_valid(env, t, type_id)) {
		btf_verifier_log_type(env, t, "Invalid resolve state");
		err = -EINVAL;
	}

	env->log_type_id = save_log_type_id;
	return err;
}

static int btf_check_all_types(struct btf_verifier_env *env)
{
	struct btf *btf = env->btf;
	const struct btf_type *t;
	u32 type_id, i;
	int err;

	err = env_resolve_init(env);
	if (err)
		return err;

	env->phase++;
	for (i = btf->base_btf ? 0 : 1; i < btf->nr_types; i++) {
		type_id = btf->start_id + i;
		t = btf_type_by_id(btf, type_id);

		env->log_type_id = type_id;
		if (btf_type_needs_resolve(t) &&
		    !env_type_is_resolved(env, type_id)) {
			err = btf_resolve(env, t, type_id);
			if (err)
				return err;
		}

		if (btf_type_is_func_proto(t)) {
			err = btf_func_proto_check(env, t);
			if (err)
				return err;
		}

		if (btf_type_is_func(t)) {
			err = btf_func_check(env, t);
			if (err)
				return err;
		}
	}

	return 0;
}

static int btf_parse_type_sec(struct btf_verifier_env *env)
{
	const struct btf_header *hdr = &env->btf->hdr;
	int err;

	 
	if (hdr->type_off & (sizeof(u32) - 1)) {
		btf_verifier_log(env, "Unaligned type_off");
		return -EINVAL;
	}

	if (!env->btf->base_btf && !hdr->type_len) {
		btf_verifier_log(env, "No type found");
		return -EINVAL;
	}

	err = btf_check_all_metas(env);
	if (err)
		return err;

	return btf_check_all_types(env);
}

static int btf_parse_str_sec(struct btf_verifier_env *env)
{
	const struct btf_header *hdr;
	struct btf *btf = env->btf;
	const char *start, *end;

	hdr = &btf->hdr;
	start = btf->nohdr_data + hdr->str_off;
	end = start + hdr->str_len;

	if (end != btf->data + btf->data_size) {
		btf_verifier_log(env, "String section is not at the end");
		return -EINVAL;
	}

	btf->strings = start;

	if (btf->base_btf && !hdr->str_len)
		return 0;
	if (!hdr->str_len || hdr->str_len - 1 > BTF_MAX_NAME_OFFSET || end[-1]) {
		btf_verifier_log(env, "Invalid string section");
		return -EINVAL;
	}
	if (!btf->base_btf && start[0]) {
		btf_verifier_log(env, "Invalid string section");
		return -EINVAL;
	}

	return 0;
}

static const size_t btf_sec_info_offset[] = {
	offsetof(struct btf_header, type_off),
	offsetof(struct btf_header, str_off),
};

static int btf_sec_info_cmp(const void *a, const void *b)
{
	const struct btf_sec_info *x = a;
	const struct btf_sec_info *y = b;

	return (int)(x->off - y->off) ? : (int)(x->len - y->len);
}

static int btf_check_sec_info(struct btf_verifier_env *env,
			      u32 btf_data_size)
{
	struct btf_sec_info secs[ARRAY_SIZE(btf_sec_info_offset)];
	u32 total, expected_total, i;
	const struct btf_header *hdr;
	const struct btf *btf;

	btf = env->btf;
	hdr = &btf->hdr;

	 
	for (i = 0; i < ARRAY_SIZE(btf_sec_info_offset); i++)
		secs[i] = *(struct btf_sec_info *)((void *)hdr +
						   btf_sec_info_offset[i]);

	sort(secs, ARRAY_SIZE(btf_sec_info_offset),
	     sizeof(struct btf_sec_info), btf_sec_info_cmp, NULL);

	 
	total = 0;
	expected_total = btf_data_size - hdr->hdr_len;
	for (i = 0; i < ARRAY_SIZE(btf_sec_info_offset); i++) {
		if (expected_total < secs[i].off) {
			btf_verifier_log(env, "Invalid section offset");
			return -EINVAL;
		}
		if (total < secs[i].off) {
			 
			btf_verifier_log(env, "Unsupported section found");
			return -EINVAL;
		}
		if (total > secs[i].off) {
			btf_verifier_log(env, "Section overlap found");
			return -EINVAL;
		}
		if (expected_total - total < secs[i].len) {
			btf_verifier_log(env,
					 "Total section length too long");
			return -EINVAL;
		}
		total += secs[i].len;
	}

	 
	if (expected_total != total) {
		btf_verifier_log(env, "Unsupported section found");
		return -EINVAL;
	}

	return 0;
}

static int btf_parse_hdr(struct btf_verifier_env *env)
{
	u32 hdr_len, hdr_copy, btf_data_size;
	const struct btf_header *hdr;
	struct btf *btf;
	int err;

	btf = env->btf;
	btf_data_size = btf->data_size;

	if (btf_data_size <
	    offsetof(struct btf_header, hdr_len) + sizeof(hdr->hdr_len)) {
		btf_verifier_log(env, "hdr_len not found");
		return -EINVAL;
	}

	hdr = btf->data;
	hdr_len = hdr->hdr_len;
	if (btf_data_size < hdr_len) {
		btf_verifier_log(env, "btf_header not found");
		return -EINVAL;
	}

	 
	if (hdr_len > sizeof(btf->hdr)) {
		u8 *expected_zero = btf->data + sizeof(btf->hdr);
		u8 *end = btf->data + hdr_len;

		for (; expected_zero < end; expected_zero++) {
			if (*expected_zero) {
				btf_verifier_log(env, "Unsupported btf_header");
				return -E2BIG;
			}
		}
	}

	hdr_copy = min_t(u32, hdr_len, sizeof(btf->hdr));
	memcpy(&btf->hdr, btf->data, hdr_copy);

	hdr = &btf->hdr;

	btf_verifier_log_hdr(env, btf_data_size);

	if (hdr->magic != BTF_MAGIC) {
		btf_verifier_log(env, "Invalid magic");
		return -EINVAL;
	}

	if (hdr->version != BTF_VERSION) {
		btf_verifier_log(env, "Unsupported version");
		return -ENOTSUPP;
	}

	if (hdr->flags) {
		btf_verifier_log(env, "Unsupported flags");
		return -ENOTSUPP;
	}

	if (!btf->base_btf && btf_data_size == hdr->hdr_len) {
		btf_verifier_log(env, "No data");
		return -EINVAL;
	}

	err = btf_check_sec_info(env, btf_data_size);
	if (err)
		return err;

	return 0;
}

static struct btf *btf_parse(void __user *btf_data, u32 btf_data_size,
			     u32 log_level, char __user *log_ubuf, u32 log_size)
{
	struct btf_verifier_env *env = NULL;
	struct bpf_verifier_log *log;
	struct btf *btf = NULL;
	u8 *data;
	int err;

	if (btf_data_size > BTF_MAX_SIZE)
		return ERR_PTR(-E2BIG);

	env = kzalloc(sizeof(*env), GFP_KERNEL | __GFP_NOWARN);
	if (!env)
		return ERR_PTR(-ENOMEM);

	log = &env->log;
	if (log_level || log_ubuf || log_size) {
		


		log->level = log_level;
		log->ubuf = log_ubuf;
		log->len_total = log_size;

		 
		if (log->len_total < 128 || log->len_total > UINT_MAX >> 8 ||
		    !log->level || !log->ubuf) {
			err = -EINVAL;
			goto errout;
		}
	}

	btf = kzalloc(sizeof(*btf), GFP_KERNEL | __GFP_NOWARN);
	if (!btf) {
		err = -ENOMEM;
		goto errout;
	}
	env->btf = btf;

	data = kvmalloc(btf_data_size, GFP_KERNEL | __GFP_NOWARN);
	if (!data) {
		err = -ENOMEM;
		goto errout;
	}

	btf->data = data;
	btf->data_size = btf_data_size;

	if (copy_from_user(data, btf_data, btf_data_size)) {
		err = -EFAULT;
		goto errout;
	}

	err = btf_parse_hdr(env);
	if (err)
		goto errout;

	btf->nohdr_data = btf->data + btf->hdr.hdr_len;

	err = btf_parse_str_sec(env);
	if (err)
		goto errout;

	err = btf_parse_type_sec(env);
	if (err)
		goto errout;

	if (log->level && bpf_verifier_log_full(log)) {
		err = -ENOSPC;
		goto errout;
	}

	btf_verifier_env_free(env);
	refcount_set(&btf->refcnt, 1);
	return btf;

errout:
	btf_verifier_env_free(env);
	if (btf)
		btf_free(btf);
	return ERR_PTR(err);
}

extern char __weak __start_BTF[];
extern char __weak __stop_BTF[];
extern struct btf *btf_vmlinux;

#define BPF_MAP_TYPE(_id, _ops)
#define BPF_LINK_TYPE(_id, _name)
static union {
	struct bpf_ctx_convert {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	prog_ctx_type _id##_prog; \
	kern_ctx_type _id##_kern;
#include "../../include/linux/bpf_types.h"
#undef BPF_PROG_TYPE
	} *__t;
	 
	const struct btf_type *t;
} bpf_ctx_convert;
enum {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	__ctx_convert##_id,
#include "../../include/linux/bpf_types.h"
#undef BPF_PROG_TYPE
	__ctx_convert_unused,  
};
static u8 bpf_ctx_convert_map[] = {
#define BPF_PROG_TYPE(_id, _name, prog_ctx_type, kern_ctx_type) \
	[_id] = __ctx_convert##_id,
#include "../../include/linux/bpf_types.h"
#undef BPF_PROG_TYPE
	0,  
};
#undef BPF_MAP_TYPE
#undef BPF_LINK_TYPE

static const struct btf_member *
btf_get_prog_ctx_type(struct bpf_verifier_log *log, const struct btf *btf,
		      const struct btf_type *t, enum bpf_prog_type prog_type,
		      int arg)
{
	const struct btf_type *conv_struct;
	const struct btf_type *ctx_struct;
	const struct btf_member *ctx_type;
	const char *tname, *ctx_tname;

	conv_struct = bpf_ctx_convert.t;
	if (!conv_struct) {
		bpf_log(log, "btf_vmlinux is malformed\n");
		return NULL;
	}
	t = btf_type_by_id(btf, t->type);
	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (!btf_type_is_struct(t)) {
		




		return NULL;
	}
	tname = btf_name_by_offset(btf, t->name_off);
	if (!tname) {
		bpf_log(log, "arg#%d struct doesn't have a name\n", arg);
		return NULL;
	}
	 
	ctx_type = btf_type_member(conv_struct) + bpf_ctx_convert_map[prog_type] * 2;
	


	ctx_struct = btf_type_by_id(btf_vmlinux, ctx_type->type);
	if (!ctx_struct)
		 
		return NULL;
	ctx_tname = btf_name_by_offset(btf_vmlinux, ctx_struct->name_off);
	if (!ctx_tname) {
		 
		bpf_log(log, "Please fix kernel include/linux/bpf_types.h\n");
		return NULL;
	}
	






	if (strcmp(ctx_tname, tname))
		return NULL;
	return ctx_type;
}






































#if 1
static int btf_translate_to_vmlinux(struct bpf_verifier_log *log,
				     struct btf *btf,
				     const struct btf_type *t,
				     enum bpf_prog_type prog_type,
				     int arg)
{
	const struct btf_member *prog_ctx_type, *kern_ctx_type;

	prog_ctx_type = btf_get_prog_ctx_type(log, btf, t, prog_type, arg);
	if (!prog_ctx_type)
		return -ENOENT;
	kern_ctx_type = prog_ctx_type + 1;
	return kern_ctx_type->type;
}
#endif










































































#ifdef CONFIG_DEBUG_INFO_BTF_MODULES

static struct btf *btf_parse_module(const char *module_name, const void *data, unsigned int data_size)
{
	struct btf_verifier_env *env = NULL;
	struct bpf_verifier_log *log;
	struct btf *btf = NULL, *base_btf;
	int err;

	base_btf = bpf_get_btf_vmlinux();
	if (IS_ERR(base_btf))
		return base_btf;
	if (!base_btf)
		return ERR_PTR(-EINVAL);

	env = kzalloc(sizeof(*env), GFP_KERNEL | __GFP_NOWARN);
	if (!env)
		return ERR_PTR(-ENOMEM);

	log = &env->log;
	log->level = BPF_LOG_KERNEL;

	btf = kzalloc(sizeof(*btf), GFP_KERNEL | __GFP_NOWARN);
	if (!btf) {
		err = -ENOMEM;
		goto errout;
	}
	env->btf = btf;

	btf->base_btf = base_btf;
	btf->start_id = base_btf->nr_types;
	btf->start_str_off = base_btf->hdr.str_len;
	btf->kernel_btf = true;
	snprintf(btf->name, sizeof(btf->name), "%s", module_name);

	btf->data = kvmalloc(data_size, GFP_KERNEL | __GFP_NOWARN);
	if (!btf->data) {
		err = -ENOMEM;
		goto errout;
	}
	memcpy(btf->data, data, data_size);
	btf->data_size = data_size;

	err = btf_parse_hdr(env);
	if (err)
		goto errout;

	btf->nohdr_data = btf->data + btf->hdr.hdr_len;

	err = btf_parse_str_sec(env);
	if (err)
		goto errout;

	err = btf_check_all_metas(env);
	if (err)
		goto errout;

	btf_verifier_env_free(env);
	refcount_set(&btf->refcnt, 1);
	return btf;

errout:
	btf_verifier_env_free(env);
	if (btf) {
		kvfree(btf->data);
		kvfree(btf->types);
		kfree(btf);
	}
	return ERR_PTR(err);
}

#endif  

#if 1
struct btf *bpf_prog_get_target_btf(const struct bpf_prog *prog)
{
	struct bpf_prog *tgt_prog = prog->aux->dst_prog;

	if (tgt_prog)
		return tgt_prog->aux->btf;
	else
		return NULL;
}

static bool is_string_ptr(struct btf *btf, const struct btf_type *t)
{
	 
	t = btf_type_by_id(btf, t->type);

	 
	if (BTF_INFO_KIND(t->info) == BTF_KIND_CONST)
		t = btf_type_by_id(btf, t->type);

	 
	return btf_type_is_int(t) && t->size == 1;
}

bool btf_ctx_access(int off, int size, enum bpf_access_type type,
		    const struct bpf_prog *prog,
		    struct bpf_insn_access_aux *info)
{
	const struct btf_type *t = prog->aux->attach_func_proto;
	struct bpf_prog *tgt_prog = prog->aux->dst_prog;
	struct btf *btf = bpf_prog_get_target_btf(prog);
	const char *tname = prog->aux->attach_func_name;
	struct bpf_verifier_log *log = info->log;
	const struct btf_param *args;
	u32 nr_args, arg;
	int i, ret;

	if (off % 8) {
		bpf_log(log, "func '%s' offset %d is not multiple of 8\n",
			tname, off);
		return false;
	}
	arg = off / 8;
	args = (const struct btf_param *)(t + 1);
	


	nr_args = t ? btf_type_vlen(t) : MAX_BPF_FUNC_REG_ARGS;
	if (prog->aux->attach_btf_trace) {
		 
		args++;
		nr_args--;
	}

	if (arg > nr_args) {
		bpf_log(log, "func '%s' doesn't have %d-th argument\n",
			tname, arg + 1);
		return false;
	}

	if (arg == nr_args) {
		switch (prog->expected_attach_type) {
		case BPF_LSM_MAC:
		case BPF_TRACE_FEXIT:
			












			if (!t)
				return true;
			t = btf_type_by_id(btf, t->type);
			break;
		case BPF_MODIFY_RETURN:
			


			if (!t)
				return false;

			t = btf_type_skip_modifiers(btf, t->type, NULL);
			if (!btf_type_is_small_int(t)) {
				bpf_log(log,
					"ret type %s not allowed for fmod_ret\n",
					btf_kind_str[BTF_INFO_KIND(t->info)]);
				return false;
			}
			break;
		default:
			bpf_log(log, "func '%s' doesn't have %d-th argument\n",
				tname, arg + 1);
			return false;
		}
	} else {
		if (!t)
			 
			return true;
		t = btf_type_by_id(btf, args[arg].type);
	}

	 
	while (btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (btf_type_is_small_int(t) || btf_type_is_enum(t))
		 
		return true;
	if (!btf_type_is_ptr(t)) {
		bpf_log(log,
			"func '%s' arg%d '%s' has type %s. Only pointer access is allowed\n",
			tname, arg,
			__btf_name_by_offset(btf, t->name_off),
			btf_kind_str[BTF_INFO_KIND(t->info)]);
		return false;
	}

	 
	for (i = 0; i < prog->aux->ctx_arg_info_size; i++) {
		const struct bpf_ctx_arg_aux *ctx_arg_info = &prog->aux->ctx_arg_info[i];

		if (ctx_arg_info->offset == off &&
		    (ctx_arg_info->reg_type == PTR_TO_RDONLY_BUF_OR_NULL ||
		     ctx_arg_info->reg_type == PTR_TO_RDWR_BUF_OR_NULL)) {
			info->reg_type = ctx_arg_info->reg_type;
			return true;
		}
	}

	if (t->type == 0)
		



		return true;

	if (is_string_ptr(btf, t))
		return true;

	 
	for (i = 0; i < prog->aux->ctx_arg_info_size; i++) {
		const struct bpf_ctx_arg_aux *ctx_arg_info = &prog->aux->ctx_arg_info[i];

		if (ctx_arg_info->offset == off) {
			info->reg_type = ctx_arg_info->reg_type;
			
			info->btf_id = ctx_arg_info->btf_id;
			return true;
		}
	}

	info->reg_type = PTR_TO_BTF_ID;
	if (tgt_prog) {
		enum bpf_prog_type tgt_type;

		if (tgt_prog->type == BPF_PROG_TYPE_EXT)
			tgt_type = tgt_prog->aux->saved_dst_prog_type;
		else
			tgt_type = tgt_prog->type;

		ret = btf_translate_to_vmlinux(log, btf, t, tgt_type, arg);
		if (ret > 0) {
			
			info->btf_id = ret;
			return true;
		} else {
			return false;
		}
	}

	
	info->btf_id = t->type;
	t = btf_type_by_id(btf, t->type);
	 
	while (btf_type_is_modifier(t)) {
		info->btf_id = t->type;
		t = btf_type_by_id(btf, t->type);
	}
	if (!btf_type_is_struct(t)) {
		bpf_log(log,
			"func '%s' arg%d type %s is not a struct\n",
			tname, arg, btf_kind_str[BTF_INFO_KIND(t->info)]);
		return false;
	}
	bpf_log(log, "func '%s' arg%d has btf_id %d type %s '%s'\n",
		tname, arg, info->btf_id, btf_kind_str[BTF_INFO_KIND(t->info)],
		__btf_name_by_offset(btf, t->name_off));
	return true;
}
#endif




































































































































































































































































































































static int __get_type_size(struct btf *btf, u32 btf_id,
			   const struct btf_type **bad_type)
{
	const struct btf_type *t;

	if (!btf_id)
		 
		return 0;
	t = btf_type_by_id(btf, btf_id);
	while (t && btf_type_is_modifier(t))
		t = btf_type_by_id(btf, t->type);
	if (!t) {
		*bad_type = btf_type_by_id(btf, 0);
		return -EINVAL;
	}
	if (btf_type_is_ptr(t))
		 
		return sizeof(void *);
	if (btf_type_is_int(t) || btf_type_is_enum(t))
		return t->size;
	*bad_type = t;
	return -EINVAL;
}

int btf_distill_func_proto(struct bpf_verifier_log *log,
			   struct btf *btf,
			   const struct btf_type *func,
			   const char *tname,
			   struct btf_func_model *m)
{
	const struct btf_param *args;
	const struct btf_type *t;
	u32 i, nargs;
	int ret;

	if (!func) {
		


		for (i = 0; i < MAX_BPF_FUNC_REG_ARGS; i++)
			m->arg_size[i] = 8;
		m->ret_size = 8;
		m->nr_args = MAX_BPF_FUNC_REG_ARGS;
		return 0;
	}
	args = (const struct btf_param *)(func + 1);
	nargs = btf_type_vlen(func);
	if (nargs >= MAX_BPF_FUNC_ARGS) {
		bpf_log(log,
			"The function %s has %d arguments. Too many.\n",
			tname, nargs);
		return -EINVAL;
	}
	ret = __get_type_size(btf, func->type, &t);
	if (ret < 0) {
		bpf_log(log,
			"The function %s return type %s is unsupported.\n",
			tname, btf_kind_str[BTF_INFO_KIND(t->info)]);
		return -EINVAL;
	}
	m->ret_size = ret;

	for (i = 0; i < nargs; i++) {
		if (i == nargs - 1 && args[i].type == 0) {
			bpf_log(log,
				"The function %s with variable args is unsupported.\n",
				tname);
			return -EINVAL;
		}
		ret = __get_type_size(btf, args[i].type, &t);
		if (ret < 0) {
			bpf_log(log,
				"The function %s arg%d type %s is unsupported.\n",
				tname, i, btf_kind_str[BTF_INFO_KIND(t->info)]);
			return -EINVAL;
		}
		if (ret == 0) {
			bpf_log(log,
				"The function %s has malformed void argument.\n",
				tname);
			return -EINVAL;
		}
		m->arg_size[i] = ret;
	}
	m->nr_args = nargs;
	return 0;
}

#if 1








static int btf_check_func_type_match(struct bpf_verifier_log *log,
				     struct btf *btf1, const struct btf_type *t1,
				     struct btf *btf2, const struct btf_type *t2)
{
	const struct btf_param *args1, *args2;
	const char *fn1, *fn2, *s1, *s2;
	u32 nargs1, nargs2, i;

	fn1 = btf_name_by_offset(btf1, t1->name_off);
	fn2 = btf_name_by_offset(btf2, t2->name_off);

	if (btf_func_linkage(t1) != BTF_FUNC_GLOBAL) {
		bpf_log(log, "%s() is not a global function\n", fn1);
		return -EINVAL;
	}
	if (btf_func_linkage(t2) != BTF_FUNC_GLOBAL) {
		bpf_log(log, "%s() is not a global function\n", fn2);
		return -EINVAL;
	}

	t1 = btf_type_by_id(btf1, t1->type);
	if (!t1 || !btf_type_is_func_proto(t1))
		return -EFAULT;
	t2 = btf_type_by_id(btf2, t2->type);
	if (!t2 || !btf_type_is_func_proto(t2))
		return -EFAULT;

	args1 = (const struct btf_param *)(t1 + 1);
	nargs1 = btf_type_vlen(t1);
	args2 = (const struct btf_param *)(t2 + 1);
	nargs2 = btf_type_vlen(t2);

	if (nargs1 != nargs2) {
		bpf_log(log, "%s() has %d args while %s() has %d args\n",
			fn1, nargs1, fn2, nargs2);
		return -EINVAL;
	}

	t1 = btf_type_skip_modifiers(btf1, t1->type, NULL);
	t2 = btf_type_skip_modifiers(btf2, t2->type, NULL);
	if (t1->info != t2->info) {
		bpf_log(log,
			"Return type %s of %s() doesn't match type %s of %s()\n",
			btf_type_str(t1), fn1,
			btf_type_str(t2), fn2);
		return -EINVAL;
	}

	for (i = 0; i < nargs1; i++) {
		t1 = btf_type_skip_modifiers(btf1, args1[i].type, NULL);
		t2 = btf_type_skip_modifiers(btf2, args2[i].type, NULL);

		if (t1->info != t2->info) {
			bpf_log(log, "arg%d in %s() is %s while %s() has %s\n",
				i, fn1, btf_type_str(t1),
				fn2, btf_type_str(t2));
			return -EINVAL;
		}
		if (btf_type_has_size(t1) && t1->size != t2->size) {
			bpf_log(log,
				"arg%d in %s() has size %d while %s() has %d\n",
				i, fn1, t1->size,
				fn2, t2->size);
			return -EINVAL;
		}

		



		if (btf_type_is_int(t1) || btf_type_is_enum(t1))
			continue;
		if (!btf_type_is_ptr(t1)) {
			bpf_log(log,
				"arg%d in %s() has unrecognized type\n",
				i, fn1);
			return -EINVAL;
		}
		t1 = btf_type_skip_modifiers(btf1, t1->type, NULL);
		t2 = btf_type_skip_modifiers(btf2, t2->type, NULL);
		if (!btf_type_is_struct(t1)) {
			bpf_log(log,
				"arg%d in %s() is not a pointer to context\n",
				i, fn1);
			return -EINVAL;
		}
		if (!btf_type_is_struct(t2)) {
			bpf_log(log,
				"arg%d in %s() is not a pointer to context\n",
				i, fn2);
			return -EINVAL;
		}
		





		s1 = btf_name_by_offset(btf1, t1->name_off);
		s2 = btf_name_by_offset(btf2, t2->name_off);
		if (strcmp(s1, s2)) {
			bpf_log(log,
				"arg%d %s(struct %s *) doesn't match %s(struct %s *)\n",
				i, fn1, s1, fn2, s2);
			return -EINVAL;
		}
	}
	return 0;
}

 
int btf_check_type_match(struct bpf_verifier_log *log, const struct bpf_prog *prog,
			 struct btf *btf2, const struct btf_type *t2)
{
	struct btf *btf1 = prog->aux->btf;
	const struct btf_type *t1;
	u32 btf_id = 0;

	if (!prog->aux->func_info) {
		bpf_log(log, "Program extension requires BTF\n");
		return -EINVAL;
	}

	btf_id = prog->aux->func_info[0].type_id;
	if (!btf_id)
		return -EFAULT;

	t1 = btf_type_by_id(btf1, btf_id);
	if (!t1 || !btf_type_is_func(t1))
		return -EFAULT;

	return btf_check_func_type_match(log, btf1, t1, btf2, t2);
}
#endif











static int btf_check_func_arg_match(struct bpf_verifier_env *env,
				    const struct btf *btf, u32 func_id,
				    struct bpf_reg_state *regs,
				    bool ptr_to_mem_ok)
{
	struct bpf_verifier_log *log = &env->log;
	const char *func_name, *ref_tname;
	const struct btf_type *t, *ref_t;
	const struct btf_param *args;
	u32 i, nargs, ref_id;

	return 0;

	t = btf_type_by_id(btf, func_id);
	if (!t || !btf_type_is_func(t)) {
		


		bpf_log(log, "BTF of func_id %u doesn't point to KIND_FUNC\n",
			func_id);
		return -EFAULT;
	}
	func_name = btf_name_by_offset(btf, t->name_off);

	t = btf_type_by_id(btf, t->type);
	if (!t || !btf_type_is_func_proto(t)) {
		bpf_log(log, "Invalid BTF of func %s\n", func_name);
		return -EFAULT;
	}
	args = (const struct btf_param *)(t + 1);
	nargs = btf_type_vlen(t);
	if (nargs > MAX_BPF_FUNC_REG_ARGS) {
		bpf_log(log, "Function %s has %d > %d args\n", func_name, nargs,
			MAX_BPF_FUNC_REG_ARGS);
		return -EINVAL;
	}

	


	for (i = 0; i < nargs; i++) {
		u32 regno = i + 1;
		struct bpf_reg_state *reg = &regs[regno];

		t = btf_type_skip_modifiers(btf, args[i].type, NULL);
		if (btf_type_is_scalar(t)) {
			if (reg->type == SCALAR_VALUE)
				continue;
			bpf_log(log, "R%d is not a scalar\n", regno);
			return -EINVAL;
		}

		if (!btf_type_is_ptr(t)) {
			bpf_log(log, "Unrecognized arg#%d type %s\n",
				i, btf_type_str(t));
			return -EINVAL;
		}

		ref_t = btf_type_skip_modifiers(btf, t->type, &ref_id);
		ref_tname = btf_name_by_offset(btf, ref_t->name_off);









































		if (0) {
		} else if (btf_get_prog_ctx_type(log, btf, t,
						 env->prog->type, i)) {
			


			if (reg->type != PTR_TO_CTX) {
				bpf_log(log,
					"arg#%d expected pointer to ctx, but got %s\n",
					i, btf_type_str(t));
				return -EINVAL;
			}
			if (check_ctx_reg(env, reg, regno))
				return -EINVAL;
		} else if (ptr_to_mem_ok) {
			const struct btf_type *resolve_ret;
			u32 type_size;

			resolve_ret = btf_resolve_size(btf, ref_t, &type_size);
			if (IS_ERR(resolve_ret)) {
				bpf_log(log,
					"arg#%d reference type('%s %s') size cannot be determined: %ld\n",
					i, btf_type_str(ref_t), ref_tname,
					PTR_ERR(resolve_ret));
				return -EINVAL;
			}

			if (check_mem_reg(env, reg, regno, type_size))
				return -EINVAL;
		} else {
			return -EINVAL;
		}
	}

	return 0;
}








int btf_check_subprog_arg_match(struct bpf_verifier_env *env, int subprog,
				struct bpf_reg_state *regs)
{
	struct bpf_prog *prog = env->prog;
	struct btf *btf = prog->aux->btf;
	bool is_global;
	u32 btf_id;
	int err;

	if (!prog->aux->func_info)
		return -EINVAL;

	btf_id = prog->aux->func_info[subprog].type_id;
	if (!btf_id)
		return -EFAULT;

#if 1
	if (prog->aux->func_info_aux[subprog].unreliable)


#endif
		return -EINVAL;

#if 1
	is_global = prog->aux->func_info_aux[subprog].linkage == BTF_FUNC_GLOBAL;


#endif
	err = btf_check_func_arg_match(env, btf, btf_id, regs, is_global);

	



	if (err)
#if 1
		prog->aux->func_info_aux[subprog].unreliable = true;


#endif
	return err;
}

int orbpf_btf_check_kfunc_arg_match(struct bpf_verifier_env *env,
			      const struct btf *btf, u32 func_id,
			      struct bpf_reg_state *regs)
{
	return btf_check_func_arg_match(env, btf, func_id, regs, false);
}
























































































































static void btf_type_show(const struct btf *btf, u32 type_id, void *obj,
			  struct btf_show *show)
{
	const struct btf_type *t = btf_type_by_id(btf, type_id);

	show->btf = btf;
	memset(&show->state, 0, sizeof(show->state));
	memset(&show->obj, 0, sizeof(show->obj));

	btf_type_ops(t)->show(btf, t, type_id, obj, 0, show);
}

static void btf_seq_show(struct btf_show *show, const char *fmt,
			 va_list args)
{
	seq_vprintf((struct seq_file *)show->target, fmt, args);
}

int btf_type_seq_show_flags(const struct btf *btf, u32 type_id,
			    void *obj, struct seq_file *m, u64 flags)
{
	struct btf_show sseq;

	sseq.target = m;
	sseq.showfn = btf_seq_show;
	sseq.flags = flags;

	btf_type_show(btf, type_id, obj, &sseq);

	return sseq.state.status;
}

void btf_type_seq_show(const struct btf *btf, u32 type_id, void *obj,
		       struct seq_file *m)
{
	(void) btf_type_seq_show_flags(btf, type_id, obj, m,
				       BTF_SHOW_NONAME | BTF_SHOW_COMPACT |
				       BTF_SHOW_ZERO | BTF_SHOW_UNSAFE);
}

struct btf_show_snprintf {
	struct btf_show show;
	int len_left;		 
	int len;		 
};

static void btf_snprintf_show(struct btf_show *show, const char *fmt,
			      va_list args)
{
	struct btf_show_snprintf *ssnprintf = (struct btf_show_snprintf *)show;
	int len;

	len = vsnprintf(show->target, ssnprintf->len_left, fmt, args);

	if (len < 0) {
		ssnprintf->len_left = 0;
		ssnprintf->len = len;
	} else if (len > ssnprintf->len_left) {
		 
		ssnprintf->len_left = 0;
		ssnprintf->len += len;
	} else {
		ssnprintf->len_left -= len;
		ssnprintf->len += len;
		show->target += len;
	}
}

int btf_type_snprintf_show(const struct btf *btf, u32 type_id, void *obj,
			   char *buf, int len, u64 flags)
{
	struct btf_show_snprintf ssnprintf;

	ssnprintf.show.target = buf;
	ssnprintf.show.flags = flags;
	ssnprintf.show.showfn = btf_snprintf_show;
	ssnprintf.len_left = len;
	ssnprintf.len = 0;

	btf_type_show(btf, type_id, obj, (struct btf_show *)&ssnprintf);

	 
	if (ssnprintf.show.state.status)
		return ssnprintf.show.state.status;

	 
	return ssnprintf.len;
}

#ifdef CONFIG_PROC_FS
static void bpf_btf_show_fdinfo(struct seq_file *m, struct file *filp)
{
	const struct btf *btf = filp->private_data;

	seq_printf(m, "btf_id:\t%u\n", btf->id);
}
#endif

static int btf_release(struct inode *inode, struct file *filp)
{
	struct btf *btf = filp->private_data;
	orbpf_btf_put(btf);
	return 0;
}

const struct file_operations orbpf_btf_fops = {
	.owner		= THIS_MODULE,
#ifdef CONFIG_PROC_FS
	.show_fdinfo	= bpf_btf_show_fdinfo,
#endif
	.release	= btf_release,
};

static int __btf_new_fd(struct btf *btf)
{
	return anon_inode_getfd("btf", &orbpf_btf_fops, btf, O_RDONLY | O_CLOEXEC);
}

int orbpf_btf_new_fd(const union bpf_attr *attr)
{
	struct btf *btf;
	int ret;

	btf = btf_parse(u64_to_user_ptr(attr->btf),
			attr->btf_size, attr->btf_log_level,
			u64_to_user_ptr(attr->btf_log_buf),
			attr->btf_log_size);
	if (IS_ERR(btf))
		return PTR_ERR(btf);

	ret = orbpf_btf_alloc_id(btf);
	if (ret) {
		btf_free(btf);
		return ret;
	}

	





	ret = __btf_new_fd(btf);

	if (ret < 0)
		orbpf_btf_put(btf);

	return ret;
}

struct btf *btf_get_by_fd(int fd)
{
	struct btf *btf;
	struct fd f;

	f = fdget(fd);

	if (!f.file)
		return ERR_PTR(-EBADF);

	if (f.file->f_op != &orbpf_btf_fops) {
		fdput(f);
		return ERR_PTR(-EINVAL);
	}

	btf = f.file->private_data;
	refcount_inc(&btf->refcnt);
	fdput(f);

	return btf;
}

int btf_get_info_by_fd(const struct btf *btf,
		       const union bpf_attr *attr,
		       union bpf_attr __user *uattr)
{
	struct bpf_btf_info __user *uinfo;
	struct bpf_btf_info info;
	u32 info_copy, btf_copy;
	void __user *ubtf;
	char __user *uname;
	u32 uinfo_len, uname_len, name_len;
	int ret = 0;

	uinfo = u64_to_user_ptr(attr->info.info);
	uinfo_len = attr->info.info_len;

	info_copy = min_t(u32, uinfo_len, sizeof(info));
	memset(&info, 0, sizeof(info));
	if (copy_from_user(&info, uinfo, info_copy))
		return -EFAULT;

	info.id = btf->id;
	ubtf = u64_to_user_ptr(info.btf);
	btf_copy = min_t(u32, btf->data_size, info.btf_size);
	if (copy_to_user(ubtf, btf->data, btf_copy))
		return -EFAULT;
	info.btf_size = btf->data_size;

	info.kernel_btf = btf->kernel_btf;

	uname = u64_to_user_ptr(info.name);
	uname_len = info.name_len;
	if (!uname ^ !uname_len)
		return -EINVAL;

	name_len = strlen(btf->name);
	info.name_len = name_len;

	if (uname) {
		if (uname_len >= name_len + 1) {
			if (copy_to_user(uname, btf->name, name_len + 1))
				return -EFAULT;
		} else {
			char zero = '\0';

			if (copy_to_user(uname, btf->name, uname_len - 1))
				return -EFAULT;
			if (put_user(zero, uname + uname_len - 1))
				return -EFAULT;
			 
			ret = -ENOSPC;
		}
	}

	if (copy_to_user(uinfo, &info, info_copy) ||
	    put_user(info_copy, &uattr->info.info_len))
		return -EFAULT;

	return ret;
}

int btf_get_fd_by_id(u32 id)
{
	struct btf *btf;
	int fd;

	rcu_read_lock();
	btf = idr_find(orbpf_btf_idr_ptr, id);
	if (!btf || !refcount_inc_not_zero(&btf->refcnt))
		btf = ERR_PTR(-ENOENT);
	rcu_read_unlock();

	if (IS_ERR(btf))
		return PTR_ERR(btf);

	fd = __btf_new_fd(btf);
	if (fd < 0)
		orbpf_btf_put(btf);

	return fd;
}

u32 btf_obj_id(const struct btf *btf)
{
	return btf->id;
}













#if 1
static int btf_id_cmp_func(const void *a, const void *b)
{
	const int *pa = a, *pb = b;

	return *pa - *pb;
}

bool btf_id_set_contains(const struct btf_id_set *set, u32 id)
{
	return bsearch(&id, set->ids, set->cnt, sizeof(u32), btf_id_cmp_func) != NULL;
}
#endif