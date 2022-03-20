# Linux Usermode Driver Platform

This is a Linux kernel module to allow userland applications to interface with hardware directly, similar to how drivers are implemented in microkernel systems, such as MINIX.

This is an academic project.

## Requirements

* GCC, Make, and other build dependencies of the Linux kernel
* The kernel headers for the kernel you're using
* DKMS (optional)

## Building

You can invoke `make` directly to build the module.

Alternatively, DKMS can be used to build and install it:

    # dkms add umdp/
    # dkms build umdp/0.1.0
    # dkms install umdp/0.1.0

## Usage

Load the module with:

    # modprobe umdp
