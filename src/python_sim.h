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

typedef struct psimi_generic_file_sd psimi_generic_file_td;

/* routines callable from data-path */
extern int psim_i2c_rdwr_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, struct i2c_rdwr_ioctl_data *i2c_rdwr_req, int *ret);
extern void *psim_emulate_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
extern int psim_simplestruct_ioctl_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, void *arg, int *ret);
extern psimi_generic_file_td *psim_generic_file_open(const char *dev_path);
extern void psim_generic_file_close(psimi_generic_file_td *psim_generic_file_handle);

extern ssize_t psim_generic_file_write(psimi_generic_file_td *psim_generic_file_handle, const void *buf,
				       size_t count);
extern ssize_t psim_generic_file_read(psimi_generic_file_td *psim_generic_file_handle, const void *buf,
				      size_t count);
extern IOCTL_REQUEST_TYPE psim_EVIOCGSW(int blen);
#endif /* __PYTHON_SIM_H */
