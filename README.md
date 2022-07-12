# Linux Usermode Driver Platform

This is a Linux kernel module to allow userland applications to interface with hardware directly, similar to how drivers are implemented in microkernel systems, such as MINIX.

This is an academic project.

## Requirements

### Kernel module

* GCC, Make, and other build dependencies of the Linux kernel
* The kernel headers for the kernel you're using
* DKMS (optional)

### Library

* A C11 compiler toolchain
* [Meson](https://mesonbuild.com)

## Building

### Kernel module

You can invoke `make` directly to build the module:

    $ cd umdp
    $ make

Alternatively, DKMS can be used to build and install it:

    # dkms add umdp/
    # dkms build umdp/0.1.0
    # dkms install umdp/0.1.0

### Library

The library can be built using Meson:

    $ cd libumdp
    $ meson setup build/
    $ meson compile -C build/

To install it, use:

    # meson install -C build/

Meson will install the library to `/usr/local/`. To install it to a different location, use the `--prefix` flag.

It can also be used (without requiring installation) as a Meson subproject.

### Examples

To build the examples, pass `-D examples=true` to the `meson setup` command when setting up the build,
or run `meson configure -D examples=true build/` to enable them on an already configured Meson build directory, then build the project like before.

## Usage

Load the module with:

    # modprobe umdp

Alternatively, if not installed, it can be loaded directly with:

    # insmod umdp.ko
