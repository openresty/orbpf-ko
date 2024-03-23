/* Copyright (C) by OpenResty Inc. All rights reserved. */
 
#ifndef __LINUX_RCUPDATE_TRACE_H
#define __LINUX_RCUPDATE_TRACE_H






#define rcu_read_lock_trace_held() false
#define call_rcu_tasks_trace(a, b) do { } while (0)

#endif  