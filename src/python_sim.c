
#include <sys/mman.h>
#include <fcntl.h>
#include <Python.h>
#include <linux/ioctl.h>
#include <linux/input.h>
#include "config.h"
#include "python_sim.h"
#include "debug.h"
static const char *psi_simulator_dot_py = NULL;

/* TODO: extend to multiple types! */
typedef struct _psi_i2c_callback_s {
  const char                 *psic_device_name;   /* E.G. "/dev/i2c-2" */
  uint16_t                    psic_i2c_addr;
  ps_i2c_rdwr_use_callback_fd psic_callback;
  struct _psi_i2c_callback_s *psic_next;
} psi_i2c_callback_td;

typedef struct _psi_devmem_callback_s {
  off_t                          psidmc_mem_offset;
  size_t                         psidmc_mem_length;
  void                          *psidmc_real_mem;
  struct _psi_devmem_callback_s *psidmc_next;
} psi_devmem_callback_td;

typedef struct _psi_simplestruct_ioctl_callback_s {
  const char                                 *psisc_device_name;  /* E.G. "/dev/input/by-path/platform-switches.25-event" */
  IOCTL_REQUEST_TYPE                          psisc_ioctl_request; /* what ioctl */
  ps_simplestruct_ioctl_callback_fd           psisc_callback;
  struct _psi_simplestruct_ioctl_callback_s  *psisc_next;
} psi_simplestruct_ioctl_callback_td;

static psi_i2c_callback_td *psi_i2c_callbacks = NULL;
static psi_devmem_callback_td *psi_devmem_callbacks = NULL;
static psi_simplestruct_ioctl_callback_td *psi_simplestruct_ioctl_callbacks = NULL;


static psi_i2c_callback_td *
psi_i2c_callback_find(const char *device, uint16_t i2c_addr) {
  psi_i2c_callback_td *cb = psi_i2c_callbacks;

  while (cb != NULL) {
    if ((strcmp(cb->psic_device_name, device) == 0) && (cb->psic_i2c_addr == i2c_addr)) {
      return cb;
    }
    cb = cb->psic_next;
  }
  return NULL;
}

static void
psi_hex_dump(FILE *fp, void *addr, size_t len) {
  uint8_t *char_addr = (uint8_t *)addr;
  uint8_t *last_addr = char_addr + len;
  uint8_t *aligned_addr = addr;
  off_t offset = 0;
  int binx;

  fprintf(fp, "----dumping 0x%x at %p----\n", len, char_addr);
  char_addr = (uint8_t *)aligned_addr;
  while (char_addr < last_addr) {
    fprintf(fp, "%p(0x%04lx): ", char_addr, offset);
    for (binx = 0; binx < 16; binx++) {
      if (char_addr < (uint8_t *)addr) {
	fprintf(fp, "-- ");
      } else if (char_addr >= last_addr) {
	fprintf(fp, "++ ");
      } else {
	fprintf(fp, "%02x ", *char_addr);
      }
      char_addr++;
      offset++;
    }
    fprintf(fp, "\n");
  }
}
    
static psi_devmem_callback_td *
psi_devmem_callback_find(off_t requested_map_addr) {
  psi_devmem_callback_td *cb = psi_devmem_callbacks;

  /*
   * NOTE: delibertly using %lx vs abstract off_t formatter, since #include order affects
   *   what off_t is (long long vs just long). Don't really care, but it needs to be consistent!!!
   *   This way, we KNOW it's just a long. always.
   */
  while (cb != NULL) {
    off_t end_of_cb_mem = cb->psidmc_mem_offset + cb->psidmc_mem_length;
    /* TODO: find available bool-type */
    
    if ((requested_map_addr >= cb->psidmc_mem_offset) && (requested_map_addr < end_of_cb_mem)) {
      return cb;
    }
    cb = cb->psidmc_next;
  }
  return NULL;
}

#if 0
static void
psi_ioctl_request_to_string(char *buffer, size_t blen, IOCTL_REQUEST_TYPE request) {
  /* todo: actually make length-safe */
  uint8_t dir;
  uint8_t type;
  uint8_t nr;
  uint16_t size;

  dir = _IOC_DIR(request);
  type = _IOC_TYPE(request);
  nr = _IOC_NR(request);
  size = _IOC_SIZE(request);

  snprintf(buffer, blen - 1, "D:%x-T:%02x-N:%02x-S:%03x", dir, type, nr, size);
}
#endif

static psi_simplestruct_ioctl_callback_td *
psi_simplestruct_ioctl_callback_find(const char *device, IOCTL_REQUEST_TYPE request) {
  uint8_t request_type, cb_type;
  psi_simplestruct_ioctl_callback_td *cb = psi_simplestruct_ioctl_callbacks;

  /*
   * We ONLY care about the type here. TODOQ: maybe look further at "nr" amd direction?
   */
  request_type = _IOC_TYPE(request);
  while (cb != NULL) {
    cb_type = _IOC_TYPE(cb->psisc_ioctl_request);
    
    if ((strcmp(cb->psisc_device_name, device) == 0) && (request_type == cb_type)) {
      fprintf(stderr, "%s@%d: FOUND!\n", __FILE__, __LINE__);
      return cb;
    }
    cb = cb->psisc_next;
  }
  fprintf(stderr, "%s@%d: NOT FOUND! sob\n", __FILE__, __LINE__);
  return NULL;
}


/*
 * function: psim_register_i2c_rdwr_use_callback
 *
 */
void
psim_register_i2c_rdwr_use_callback(const char *dev_path, uint16_t i2c_addr, ps_i2c_rdwr_use_callback_fd cb) {
  psi_i2c_callback_td *new_cb, *existing;

  existing = psi_i2c_callback_find(dev_path, i2c_addr);
  if (existing) {
    DBG(DBG_PSI, "%s@%d: callback for %s:%04x already existed, but adding anyway.\n",
	__FILE__, __LINE__, dev_path, i2c_addr);
  }
  new_cb = calloc(sizeof(psi_i2c_callback_td), 1);
  assert(new_cb != NULL);
  new_cb->psic_device_name = strdup(dev_path);
  new_cb->psic_i2c_addr = i2c_addr;
  new_cb->psic_callback = cb;
  new_cb->psic_next = psi_i2c_callbacks;
  psi_i2c_callbacks = new_cb;
}

void
psim_register_devmem(off_t map_offset, size_t mem_size, void *real_addr) {
  psi_devmem_callback_td *new_cb, *existing;
  
  existing = psi_devmem_callback_find(map_offset);
  if (existing) {
    DBG(DBG_PSI, "%s@%d: memmap for 0x%lx already existed. Goodbye.\n", __FILE__, __LINE__, map_offset);
    abort();
  }
  //psi_hex_dump(stderr, real_addr, mem_size);
  new_cb = calloc(sizeof(psi_devmem_callback_td), 1);
  assert(new_cb != NULL);
  new_cb->psidmc_mem_offset = map_offset;
  new_cb->psidmc_mem_length = mem_size;
  new_cb->psidmc_real_mem = real_addr;
  new_cb->psidmc_next = psi_devmem_callbacks;
  psi_devmem_callbacks = new_cb;
}


void *
psim_emulate_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  psi_devmem_callback_td *cb;

  assert(addr == NULL);   /* must use kernel-given addresses here */
  cb = psi_devmem_callback_find(offset);
  if (cb == NULL) {
    fprintf(stderr, "%s@%d: did not find 0x%0lx in any maps. Returning EINVAL\n", __FILE__, __LINE__, offset);
    errno = EINVAL;
    return MAP_FAILED;
  }
  fprintf(stderr, "%s@%d WE FOUND MEMORY, returning %p!!!!\n", __FILE__, __LINE__, cb->psidmc_real_mem);
  assert(offset == cb->psidmc_mem_offset);   /* TODO: handle mapping inside memspace */
  if (addr != NULL)  psi_hex_dump(stderr, cb->psidmc_real_mem, length);
  return cb->psidmc_real_mem;
}

/*
 * function: psim_constructor()
 * 
 * Checks for if the UMOCKDEV_PYTHON_SIMULATOR is set, and if so initialize the
 * python interpreter along with any required registration methods and then fire up
 * the script found in UMOCKDEV_PYTHON_SIMULATOR.
 *
 * Note that UMOCKDEV_PYTHON_SIMULATOR needs to return for us to continue, but
 * that doesn't mean it can't leave something running!
 */
void
psim_constructor(void) {
  FILE *sfile;

  DBG(DBG_PSI, "%s@%d: python is available for python based active simulation.\n", __FILE__, __LINE__);

  psi_simulator_dot_py = getenv("UMOCKDEV_PYTHON_SIMULATOR");
  if (psi_simulator_dot_py == NULL) {
    DBG(DBG_PSI, "%s@%d: UMOCKDEV_PYTHON_SIMULATOR env not defined. Not activating python.\n", __FILE__, __LINE__);
  } else {
    DBG(DBG_PSI, "%s@%d: UMOCKDEV_PYTHON_SIMULATOR is '%s'. Activating python.\n", __FILE__, __LINE__, psi_simulator_dot_py);

    /* TODO: Py_SetProgramName((wchar_t *)python_prog_name);  optional but recommended */
    Py_Initialize();

    sfile = fopen(psi_simulator_dot_py, "r");
    if (sfile == NULL) {
      DBG(DBG_PSI, "%s@%d: Unable to open '%s' to run in python because %d(%s). Simulator unavailable.\n",
	  __FILE__, __LINE__, psi_simulator_dot_py, errno, strerror(errno));
      /* TODOQ: should this abort instead? */
    } else {
      DBG(DBG_PSI, "%s@%d: executing '%s'...\n", __FILE__, __LINE__, psi_simulator_dot_py);
      if (PyRun_AnyFile(sfile, psi_simulator_dot_py)) {
	/* note, if the run failed, stuff will haev printed on stderr about why. */
	DBG(DBG_PSI, "%s@%d:   --run failed! see preceeding backtrace--\n", __FILE__, __LINE__);
	abort();
      }
      DBG(DBG_PSI, "%s@%d: python-simulator has been run and is active.\n", __FILE__, __LINE__);
      fclose(sfile);
    }
  }
  const char *name = "/tmp/status.py";
  sfile = fopen("/tmp/status.py", "r");
  assert(sfile != NULL);
  DBG(DBG_PSI, "%s@%d: executing TODO: remopve '%s'...\n", __FILE__, __LINE__, name);
  if (PyRun_AnyFile(sfile, name)) {
    /* note, if the run failed, stuff will haev printed on stderr about why. */
    DBG(DBG_PSI, "%s@%d:   --run failed! see preceeding backtrace--\n", __FILE__, __LINE__);
    abort();
  }
  DBG(DBG_PSI, "%s@%d: python-simulator has been run and is active.\n", __FILE__, __LINE__);
  fclose(sfile);

  fprintf(stderr, "%s@%d: Trying to check-grab GIL....\n", __FILE__, __LINE__);
  PyGILState_STATE gstate;
  gstate = PyGILState_Ensure();
  fprintf(stderr, "..... GOTIT!!!!!\n");
  PyGILState_Release(gstate);
  fprintf(stderr, ".... gace it away\n");
}

void
psim_destructor(void) {
  DBG(DBG_PSI, "%s@%d: psim_destructor called.\n", __FILE__, __LINE__);
  /* TODOQ: clean up callbacks. */
}

int
psim_i2c_rdwr_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, struct i2c_rdwr_ioctl_data *rdwr_req, int *ret) {
  psi_i2c_callback_td *our_cb;
  struct i2c_msg *a_msg;
  uint16_t found_addr = 0;
  size_t msg_n;

  if (rdwr_req->nmsgs == 0) {
    DBG(DBG_PSI, "%s@%d: can't match without any contained messages.\n", __FILE__, __LINE__);
    return 0;
  }

  found_addr = rdwr_req->msgs[0].addr;
  for (msg_n = 0; msg_n < rdwr_req->nmsgs; msg_n++) {
    a_msg = &rdwr_req->msgs[msg_n];
    if (a_msg->addr != found_addr) {
      DBG(DBG_PSI, "%s@%d: i2c_rdwr_ioctl had multiple addresses in it (0x%04x 0x%04x). Skipping\n",
	  __FILE__, __LINE__, found_addr, a_msg->addr);
      return 0;
    }
  }
  our_cb = psi_i2c_callback_find(dev, found_addr);
  if (our_cb == NULL) {
    DBG(DBG_PSI, "%s@%d: did not find %s(0x%04x) in callbacks\n", __FILE__, __LINE__, dev, found_addr);
    return 0;
  }
  DBG(DBG_PSI, "%s@%d: going to GIL for %s(0x%04x)\n", __FILE__, __LINE__, dev, found_addr);

  PyGILState_STATE gstate;
  gstate = PyGILState_Ensure();
  DBG(DBG_PSI, "%s@%d: going to call callback for %s(0x%04x)\n", __FILE__, __LINE__, dev, found_addr);
  our_cb->psic_callback(dev, rdwr_req, id, found_addr);
  DBG(DBG_PSI, "%s@%d: DONE with callback for %s(0x%04x)\n", __FILE__, __LINE__, dev, found_addr);
  /* Release the thread. No Python API allowed beyond this point. */
  PyGILState_Release(gstate);
  DBG(DBG_PSI, "%s@%d: DONE with unGIL for %s(0x%04x)\n", __FILE__, __LINE__, dev, found_addr);

#if 0
  for (msg_n = 0; msg_n < rdwr_req->nmsgs; msg_n++) {
    a_msg = &rdwr_req->msgs[msg_n];
    fprintf(stderr, "%02d of %02d: addr=0x%04x, flags=0x%04x, len=%d, buf=%p ->",
	    msg_n, rdwr_req->nmsgs, a_msg->addr, a_msg->flags, a_msg->len, a_msg->buf);
    psi_hex_out(stderr, a_msg->buf, a_msg->len);
    fprintf(stderr, "\n");
  }
#endif

  return 1;
}  


/*
 * psim_simplestruct_ioctl_execute_cb()
 *
 * called by data-path code to punt a simplestruct style ioctl to the simulator.
 * Most notably, the "id" parameter is a 32 bit command packed in the _IOC style described
 * in ioctl.h. We grab all the encoded pieces, but mostly what we care about is the direction and
 * length!
 *
 * TODOQ: maybe match on mtype rather than full id?
 */
int
psim_simplestruct_ioctl_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, void *arg, int *ret) {
  psi_simplestruct_ioctl_callback_td *our_cb;
  uint32_t dir, mtype, nr, bsize;
  int handled;
  int ret_errno = 0;

  our_cb = psi_simplestruct_ioctl_callback_find(dev, id);
  if (our_cb == NULL) {
    DBG(DBG_PSI, "%s@%d: did not find %s(0x%08lx) in callbacks\n", __FILE__, __LINE__, dev, id);
    return 0;
  }
  dir = _IOC_DIR(id);
  mtype = _IOC_TYPE(id);
  nr = _IOC_TYPE(nr);
  bsize = _IOC_SIZE(nr);
  
  DBG(DBG_PSI, "%s@%d: going to GIL for %s(0x%08lx->dir=0x%x, mtype=0x%x, nr=0x%x, size=%d)\n",
      __FILE__, __LINE__, dev, id, dir, mtype, nr, bsize);
  DBG(DBG_PSI, "%s@%d:   f_ret=%p(->%d). errno=%p(->%d)\n", __FILE__, __LINE__, ret, *ret, &ret_errno,
      ret_errno);
  PyGILState_STATE gstate;
  gstate = PyGILState_Ensure();
  
  handled = our_cb->psisc_callback(dev, dir, mtype, nr, bsize, ret, &ret_errno);
  DBG(DBG_PSI, "%s@%d: callback returned for %s(0x%08lx): handled=%d, function_return=%d, errno-will-be=%d\n",
      __FILE__, __LINE__, dev, id, handled, *ret, ret_errno);
  errno = ret_errno;
  PyGILState_Release(gstate);
  DBG(DBG_PSI, "%s@%d: callback unGILed for %s(0x%08lx): handled=%d, function_return=%d, errno-will-be=%d\n",
      __FILE__, __LINE__, dev, id, handled, *ret, ret_errno);
  return handled;
}

void
psim_register_simplestruct_ioctl(const char *dev, IOCTL_REQUEST_TYPE id,
				 ps_simplestruct_ioctl_callback_fd cb_fn) {
  psi_simplestruct_ioctl_callback_td *new_cb, *existing;

  fprintf(stderr, "%s@%d: simplestruct callback register of %s 0x%08lx to %p\n",
	  __FILE__, __LINE__, dev, id, cb_fn);
  existing = psi_simplestruct_ioctl_callback_find(dev, id);
  if (existing) {
    DBG(DBG_PSI, "%s@%d: simplestruct ioctl %s 0x%08lx callback already registered.\n",
	__FILE__, __LINE__, dev, id);
    abort();
  }
  new_cb = calloc(sizeof(psi_simplestruct_ioctl_callback_td), 1);
  assert(new_cb != NULL);
  new_cb->psisc_device_name = strdup(dev);
  assert(new_cb != NULL);
  new_cb->psisc_ioctl_request = id;
  new_cb->psisc_callback = cb_fn;
  new_cb->psisc_next = psi_simplestruct_ioctl_callbacks;
  psi_simplestruct_ioctl_callbacks = new_cb;
}

/*
 * psim_EVIOCGSW()
 *
 * Allows access to compile-based value of this ioctl. Note, using a blen of 0 will yield the
 * overall ioctl "type" value.
 */
IOCTL_REQUEST_TYPE
psim_EVIOCGSW(int blen) {
  IOCTL_REQUEST_TYPE zero_len_id = EVIOCGSW(0);
  IOCTL_REQUEST_TYPE ret_id;

  ret_id = zero_len_id | ((blen) << _IOC_SIZESHIFT);
  return ret_id;
}
