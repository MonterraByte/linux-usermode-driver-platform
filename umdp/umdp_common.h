#ifndef UMDP_COMMON_H
#define UMDP_COMMON_H

struct port_io_region {
    u64 start;
    u64 size;
};

struct mmap_region {
    unsigned long start;
    unsigned long size;
};

#endif  // UMDP_COMMON_H
