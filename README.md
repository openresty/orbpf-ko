# Name

orbpf-ko - The orbpf (eBPF+) Linux kernel module from OpenResty Inc.

# Description

This Linux/Android kernel module is an enhanced version of the eBPF runtime
in the mainline Linux kernels and Android kernels.

It is also known as eBPF+.

See our [Ylang blog post series](https://blog.openresty.com/en/ylang-intro-part1/)
for more details.

Most of the safety and halting guarentees are implemented in higher level
compilers like Ylang at compile time instead of in a fatty, slow and limited
in-kernel verifier.

# How to build

```bash
# assuming the current working directory is the module root
# directory
KERNEL_PREFIX=/path/to/kernel/build/tree
make -C $KERNEL_PREFIX M=$PWD modules -j$(nproc)
```

# Load the module

```bash
sudo insmod orbpf.ko
```

# Unload the module

```bash
sudo rmmod orbpf
```

# Run sanity tests

```bash
gcc -o test test.c
sudo ./test
```

# Copyright

Copyright (C) by OpenResty Inc. All rights reserved.

Copyright (C) by Linux Kernel Contributors.

Copyright (c) 2023 Kirk Nickish and https://github.com/823984418

# License

GPL 2.0
