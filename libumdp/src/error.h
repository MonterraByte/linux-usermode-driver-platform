#ifndef UMDP_ERROR_H
#define UMDP_ERROR_H

#include <stdio.h>

#ifndef UMDP_DISABLE_ERROR_PRINTING
#define printf_err(format, ...) fprintf(stderr, "%s: " format, __func__, __VA_ARGS__)
#define print_err(string) fprintf(stderr, "%s: " string, __func__)
#else
#define printf_err(...)
#define print_err(string)
#endif

#endif  // UMDP_ERROR_H
