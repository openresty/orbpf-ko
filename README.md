# Name

orbpf-ko - The orbpf (eBPF+) Linux kernel module from OpenResty Inc.

# Table of Contents

* [Name](#name)
* [Description](#description)
* [How to build](#how-to-build)
* [Load the module](#load-the-module)
* [Unload the module](#unload-the-module)
* [Run sanity tests](#run-sanity-tests)
* [Copyright](#copyright)
* [License](#license)

# Description

This Linux/Android kernel module is an enhanced version of the eBPF runtime
in the mainline Linux kernels and Android kernels.

It is also known as eBPF+.

See our [Ylang blog post series](https://blog.openresty.com/en/ylang-intro-part1/)
for more details.

Some of the safety and halting guarentees are implemented in higher level
compilers like Ylang at compile time instead of relying on the in-kernel
verifier at load time.

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

[Back to TOC](#table-of-contents)

# Unload the module

```bash
sudo rmmod orbpf
```

[Back to TOC](#table-of-contents)

# Run sanity tests

```bash
gcc -o test test.c
sudo ./test
```

[Back to TOC](#table-of-contents)

# Copyright

Copyright (C) by OpenResty Inc. All rights reserved.

Copyright (C) by Linux Kernel Contributors.

Copyright (c) 2023 Kirk Nickish and https://github.com/823984418

[Back to TOC](#table-of-contents)

# License

GPL 2.0

[Back to TOC](#table-of-contents)

