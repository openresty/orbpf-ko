/* Copyright (C) by OpenResty Inc. All rights reserved. */

#ifndef _ORBPF_LINUX_BTF_IDS_H
#define _ORBPF_LINUX_BTF_IDS_H

#include <linux/orbpf_config_begin.h>  

struct btf_id_set {
	u32 cnt;
	u32 ids[];
};

#ifdef CONFIG_DEBUG_INFO_BTF











#define BTF_IDS_SECTION ".BTF_ids"

#define ____BTF_ID(symbol)				\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
".local " #symbol " ;                          \n"	\
".type  " #symbol ", STT_OBJECT;               \n"	\
".size  " #symbol ", 4;                        \n"	\
#symbol ":                                     \n"	\
".zero 4                                       \n"	\
".popsection;                                  \n");

#define __BTF_ID(symbol) \
	____BTF_ID(symbol)

#define __ID(prefix) \
	__PASTE(prefix, __COUNTER__)





#define BTF_ID(prefix, name) \
	__BTF_ID(__ID(__BTF_ID__##prefix##__##name##__))
















#define __BTF_ID_LIST(name, scope)			\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
"." #scope " " #name ";                        \n"	\
#name ":;                                      \n"	\
".popsection;                                  \n");

#define BTF_ID_LIST(name)				\
__BTF_ID_LIST(name, local)				\
extern u32 name[];

#define BTF_ID_LIST_GLOBAL(name)			\
__BTF_ID_LIST(name, globl)




#define BTF_ID_LIST_SINGLE(name, prefix, typename)	\
	BTF_ID_LIST(name) \
	BTF_ID(prefix, typename)












#define BTF_ID_UNUSED					\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
".zero 4                                       \n"	\
".popsection;                                  \n");



















#define __BTF_SET_START(name, scope)			\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";       \n"	\
"." #scope " __BTF_ID__set__" #name ";         \n"	\
"__BTF_ID__set__" #name ":;                    \n"	\
".zero 4                                       \n"	\
".popsection;                                  \n");

#define BTF_SET_START(name)				\
__BTF_ID_LIST(name, local)				\
__BTF_SET_START(name, local)

#define BTF_SET_START_GLOBAL(name)			\
__BTF_ID_LIST(name, globl)				\
__BTF_SET_START(name, globl)

#define BTF_SET_END(name)				\
asm(							\
".pushsection " BTF_IDS_SECTION ",\"a\";      \n"	\
".size __BTF_ID__set__" #name ", .-" #name "  \n"	\
".popsection;                                 \n");	\
extern struct btf_id_set name;

#else

#define BTF_ID_LIST(name) static u32 name[5];
#define BTF_ID(prefix, name)
#define BTF_ID_UNUSED
#define BTF_ID_LIST_GLOBAL(name) u32 name[1];
#define BTF_ID_LIST_SINGLE(name, prefix, typename) static u32 name[1];
#define BTF_SET_START(name) static struct btf_id_set name = { 0 };
#define BTF_SET_START_GLOBAL(name) static struct btf_id_set name = { 0 };
#define BTF_SET_END(name)

#endif  

#ifdef CONFIG_NET




#define BTF_SOCK_TYPE_xxx \
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET, inet_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_CONN, inet_connection_sock)	\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_REQ, inet_request_sock)	\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_INET_TW, inet_timewait_sock)	\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_REQ, request_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCK, sock)				\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_SOCK_COMMON, sock_common)		\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP, tcp_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP_REQ, tcp_request_sock)		\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP_TW, tcp_timewait_sock)		\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_TCP6, tcp6_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UDP, udp_sock)			\
	BTF_SOCK_TYPE(BTF_SOCK_TYPE_UDP6, udp6_sock)

enum {
#define BTF_SOCK_TYPE(name, str) name,
BTF_SOCK_TYPE_xxx
#undef BTF_SOCK_TYPE
MAX_BTF_SOCK_TYPE,
};

extern u32 btf_sock_ids[];
#endif

#include <linux/orbpf_config_end.h>  
#endif