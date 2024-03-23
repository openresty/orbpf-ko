/* Copyright (C) by OpenResty Inc. All rights reserved. */


#ifndef __MAP_IN_MAP_H__
#define __MAP_IN_MAP_H__

#include <linux/types.h>
#include <linux/orbpf_config_begin.h>  

struct file;
struct bpf_map;

struct bpf_map *bpf_map_meta_alloc(int inner_map_ufd);
void bpf_map_meta_free(struct bpf_map *map_meta);
void *bpf_map_fd_get_ptr(struct bpf_map *map, struct file *map_file,
			 int ufd);
void bpf_map_fd_put_ptr(void *ptr);
u32 bpf_map_fd_sys_lookup_elem(void *ptr);

#include <linux/orbpf_config_end.h>  
#endif