#ifndef UMDP_ACCESS_CONTROL_H
#define UMDP_ACCESS_CONTROL_H

#include <linux/types.h>

#include "umdp_common.h"

int umdp_ac_init(void);
void umdp_ac_exit(void);

bool umdp_ac_can_access_irq(const char* exe_path, u32 irq);
bool umdp_ac_can_access_port_io_region(const char* exe_path, struct port_io_region region);

#endif  // UMDP_ACCESS_CONTROL_H
