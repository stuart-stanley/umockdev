#ifndef __PYTHON_SIM_H
#define __PYTHON_SIM_H

/* TODO: iffy about including from .h, but it is isolating things. hmmm */
#include <linux/ioctl.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include "config.h"

/* setup/teardown of subsystem prototypes */
extern void psim_constructor(void);
extern void psim_destructor(void);

/* routines callable from data-path */
extern int psim_i2c_rdwr_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, struct i2c_rdwr_ioctl_data *i2c_rdwr_req, int *ret);
extern void *psim_emulate_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
extern int psim_simplestruct_ioctl_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, void *arg, int *ret);

/* routines and defines used to setup callbacks from python-space */
typedef int (*ps_simplestruct_ioctl_callback_fd)(const char *device,
					         uint8_t dir,
						 uint8_t mtype,
						 uint8_t nr,
						 uint16_t size,
						 int *fn_return,
						 int *ret_errno);
extern void psim_register_simplestruct_ioctl(const char *dev, IOCTL_REQUEST_TYPE id,
					     ps_simplestruct_ioctl_callback_fd cb_fn);
typedef int (*ps_i2c_rdwr_use_callback_fd)(const char *device,
					   struct i2c_rdwr_ioctl_data *rdwr_req,
					   IOCTL_REQUEST_TYPE ioctl_cmd,
					   uint16_t i2_addr);
extern void psim_register_i2c_rdwr_use_callback(const char *dev, uint16_t i2c_addr,
						ps_i2c_rdwr_use_callback_fd cb_fn);
extern void psim_register_devmem(off_t map_offset, size_t mem_size, void *real_addr);

extern IOCTL_REQUEST_TYPE psim_EVIOCGSW(int blen);
#endif /* __PYTHON_SIM_H */
