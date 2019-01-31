
#include <sys/mman.h>
#include <fcntl.h>
#define PY_SSIZE_T_CLEAN  /* Make "s#" use Py_ssize_t rather than int. */
#include <Python.h>
#include <linux/ioctl.h>
#include <linux/input.h>
#include <pthread.h>
#include "config.h"
#include "python_sim.h"
#include "debug.h"
static const char *psi_simulator_dot_py = NULL;

#define PPTID ((void *)pthread_self())

/* TODO: break this into WHAT is being simulated files */
/* TODO: make an python_sim_int.h file with internal structs/defines */
typedef struct psimi_generic_file_sd {
  const char                 *psigf_file_path;    /* E.G. "/sys/class/mumble/attribute" */
  PyObject                   *psigf_callback;
  psimi_generic_file_td      *psigf_next;
} psimi_generic_file_td;

/* TODO: extend to multiple types! */
typedef struct _psi_i2c_callback_s {
  const char                 *psic_device_name;   /* E.G. "/dev/i2c-2" */
  uint16_t                    psic_i2c_addr;
  PyObject                   *psic_callback;
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
  PyObject                                   *psisc_callback;
  struct _psi_simplestruct_ioctl_callback_s  *psisc_next;
} psi_simplestruct_ioctl_callback_td;

static psi_i2c_callback_td *psi_i2c_callbacks = NULL;
static psi_devmem_callback_td *psi_devmem_callbacks = NULL;
static psi_simplestruct_ioctl_callback_td *psi_simplestruct_ioctl_callbacks = NULL;
static psimi_generic_file_td *psi_generic_file_handlers = NULL;

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

#ifdef DEEP_MMAP_DEBUG
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
#endif /* DEEP_MMAP_DEBUG */
    
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

#define ALL_BUT_IOCTL_SIZE_MASK  (~(_IOC_SIZEMASK >> _IOC_SIZESHIFT))

static psi_simplestruct_ioctl_callback_td *
psi_simplestruct_ioctl_callback_find(const char *device, IOCTL_REQUEST_TYPE request) {
  IOCTL_REQUEST_TYPE request_match, cb_match;
  psi_simplestruct_ioctl_callback_td *cb = psi_simplestruct_ioctl_callbacks;

  /*
   * Check for match based on everything BUT size. 
   */
  //  fprintf(stderr, "'%s', %08x %08lx\n", device, ALL_BUT_IOCTL_SIZE_MASK, request & ALL_BUT_IOCTL_SIZE_MASK);

  request_match = request & ALL_BUT_IOCTL_SIZE_MASK;
  while (cb != NULL) {
    cb_match = cb->psisc_ioctl_request & ALL_BUT_IOCTL_SIZE_MASK;
    /*    fprintf(stderr, "%s@%d-%p: %s req:%08lx -- cbreq:%08lx m: rm:%08lx cbm:%08lx %d\n",
	    __FILE__, __LINE__, PPTID, cb->psisc_device_name,
	    request, cb->psisc_ioctl_request, request_match, cb_match, strcmp(cb->psisc_device_name, device));*/
    
    if ((strcmp(cb->psisc_device_name, device) == 0) && (request_match == cb_match)) {
      return cb;
    }
    cb = cb->psisc_next;
  }
  return NULL;
}

static psimi_generic_file_td *
psi_generic_file_handle_find(const char *file_path) {
  psimi_generic_file_td *handler = psi_generic_file_handlers;

  while (handler != NULL) {
    if (strcasecmp(handler->psigf_file_path, file_path) == 0) {
      return handler;
    }
    handler = handler->psigf_next;
  }
  return NULL;
}


/*
 * function: psim_register_i2c_rdwr_use_callback
 *
 */
static PyObject *
psim_register_i2c_rdwr_use_callback(PyObject *self, PyObject *args) {
  psi_i2c_callback_td *new_cb, *existing;
  const char *dev_path;
  uint16_t i2c_addr;
  PyObject *cb;

  if (!PyArg_ParseTuple(args, "sHO", &dev_path, &i2c_addr, &cb)) {
    return NULL;   /* failed */
  }
  if (!PyCallable_Check(cb)) {
    PyErr_SetString(PyExc_TypeError, "callback must be callable");
    return NULL;
  }
  Py_XINCREF(cb);
  existing = psi_i2c_callback_find(dev_path, i2c_addr);
  if (existing) {
    DBG(DBG_PSI, "%s@%d-%p: callback for %s:%04x already existed, but adding anyway.\n",
	__FILE__, __LINE__, PPTID, dev_path, i2c_addr);
  }
  new_cb = calloc(sizeof(psi_i2c_callback_td), 1);
  assert(new_cb != NULL);
  new_cb->psic_device_name = strdup(dev_path);
  new_cb->psic_i2c_addr = i2c_addr;
  new_cb->psic_callback = cb;
  new_cb->psic_next = psi_i2c_callbacks;
  psi_i2c_callbacks = new_cb;
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
psim_register_devmem(PyObject *self, PyObject *args) {
  psi_devmem_callback_td *new_cb, *existing;
  off_t map_offset;
  size_t mem_size;
  Py_buffer real_data;

  if (!PyArg_ParseTuple(args, "IIy*", &map_offset, &mem_size, &real_data)) {
    return NULL;   /* failed */
  }

  DBG(DBG_MMAP, "%s@%d-%p: map_offset=%x, mem_size=%d, real_data=%p->%p\n",
      __FILE__, __LINE__, PPTID, (unsigned)map_offset, mem_size, &real_data, real_data.buf);
  existing = psi_devmem_callback_find(map_offset);
  if (existing) {
    fprintf(stderr, "%s@%d-%p: memmap for 0x%lx already existed. Goodbye.\n", __FILE__, __LINE__, PPTID, map_offset);
    abort();
  }
#ifdef DEEP_MMAP_DEBUG
  psi_hex_dump(stderr, real_addr, mem_size);
#endif /* DEEP_MMAP_DEBUG */
  new_cb = calloc(sizeof(psi_devmem_callback_td), 1);
  assert(new_cb != NULL);
  new_cb->psidmc_mem_offset = map_offset;
  new_cb->psidmc_mem_length = mem_size;
  new_cb->psidmc_real_mem = real_data.buf;
  new_cb->psidmc_next = psi_devmem_callbacks;
  psi_devmem_callbacks = new_cb;
  Py_INCREF(Py_None);
  return Py_None;
}


void *
psim_emulate_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  psi_devmem_callback_td *cb;

  assert(addr == NULL);   /* must use kernel-given addresses here */
  cb = psi_devmem_callback_find(offset);
  if (cb == NULL) {
    DBG(DBG_MMAP, "%s@%d-%p: did not find 0x%0lx in any maps. Returning EINVAL\n", __FILE__, __LINE__, PPTID, offset);
    errno = EINVAL;
    return MAP_FAILED;
  }
  DBG(DBG_MMAP, "%s@%d-%p: mmap data for %ld found, returning  %p!!!!\n", __FILE__, __LINE__, PPTID, offset, cb->psidmc_real_mem);
  assert(offset == cb->psidmc_mem_offset);   /* TODO: handle mapping inside memspace */
  return cb->psidmc_real_mem;
}

static PyObject *
psim_register_simplestruct_ioctl(PyObject *self, PyObject *args) {
  psi_simplestruct_ioctl_callback_td *new_cb, *existing;
  const char *dev_path;
  IOCTL_REQUEST_TYPE id;
  PyObject *cb;


  DBG(DBG_IOCTL, "%s@%d-%p: simplestruct callback register sizeof IOCTL_REQUEST_TYPE=%d\n",
      __FILE__, __LINE__, PPTID, sizeof(IOCTL_REQUEST_TYPE));
  /* TODO: verify size of id again */
  if (!PyArg_ParseTuple(args, "skO", &dev_path, &id, &cb)) {
    return NULL;   /* failed */
  }
  if (!PyCallable_Check(cb)) {
    PyErr_SetString(PyExc_TypeError, "callback must be callable");
    return NULL;
  }
  existing = psi_simplestruct_ioctl_callback_find(dev_path, id);
  if (existing) {
    fprintf(stderr, "%s@%d-%p: simplestruct ioctl %s 0x%08lx callback already registered. Aborting.\n",
	    __FILE__, __LINE__, PPTID, dev_path, id);
    abort();
  }
  Py_XINCREF(cb);
  new_cb = calloc(sizeof(psi_simplestruct_ioctl_callback_td), 1);
  assert(new_cb != NULL);
  new_cb->psisc_device_name = strdup(dev_path);
  assert(new_cb != NULL);
  new_cb->psisc_ioctl_request = id;
  new_cb->psisc_callback = cb;
  new_cb->psisc_next = psi_simplestruct_ioctl_callbacks;
  psi_simplestruct_ioctl_callbacks = new_cb;
  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject *
psim_register_generic_file_ops(PyObject *self, PyObject *args) {
  psimi_generic_file_td *new_handler, *existing;
  const char *dev_path;
  PyObject *cb;

  if (!PyArg_ParseTuple(args, "sO", &dev_path, &cb)) {
    fprintf(stderr, "failed parse\n");
    abort();
    return NULL;   /* failed */
  }
  DBG(DBG_GF, "%s@%d-%p: generic file registration for %s.\n", __FILE__, __LINE__, PPTID, dev_path);
  if (!PyCallable_Check(cb)) {
    PyErr_SetString(PyExc_TypeError, "callback must be callable");
    return NULL;
  }
  existing = psi_generic_file_handle_find(dev_path);
  if (existing) {
    fprintf(stderr, "%s@%d-%p: generic file %s callback already registered. Aborting.\n",
	    __FILE__, __LINE__, PPTID, dev_path);
    abort();
  }
  Py_XINCREF(cb);
  new_handler = calloc(sizeof(psimi_generic_file_td), 1);
  assert(new_handler != NULL);
  new_handler->psigf_file_path = strdup(dev_path);
  assert(new_handler->psigf_file_path != NULL);
  new_handler->psigf_callback = cb;
  new_handler->psigf_next = psi_generic_file_handlers;
  psi_generic_file_handlers = new_handler;
  Py_INCREF(Py_None);
  return Py_None;
}

/* TODO: document */
static PyMethodDef UMockDevMethods[] = {
  { "psim_register_i2c_rdwr_use_callback", psim_register_i2c_rdwr_use_callback, METH_VARARGS,
    "Register i2c-rdwr useage callback" },
  { "psim_register_devmem", psim_register_devmem, METH_VARARGS,
    "Register /dev/mem mmap data" },
  { "psim_register_simplestruct_ioctl", psim_register_simplestruct_ioctl, METH_VARARGS,
    "Register simple-structure based ioctl usage callback" },
  { "psim_register_generic_file_ops", psim_register_generic_file_ops, METH_VARARGS,
    "Register generic file-io interception" },
  { NULL, NULL, 0, NULL }
};

static struct PyModuleDef umockdev_module = {
  PyModuleDef_HEAD_INIT,
  "umockdev_preload",   /* name of module */
  NULL,                 /* module documentation, may be NULL */
  -1,                   /* size of per-interpreter state of the module,
	                 or -1 if the module keeps state in global variables. */
  UMockDevMethods
};

static PyMODINIT_FUNC
PyInit_umockdev_module(void)
{
  return PyModule_Create(&umockdev_module);
}

/*
 * TOD: WTF, doco hack for using our own mutex instead of python GIL things.
 */
pthread_mutex_t psi_callback_mutext = PTHREAD_MUTEX_INITIALIZER;
static void
psi_callback_lock(const char *whom, uint32_t from_line) {
  int rc;
  int hold_errno;
  
  DBG(DBG_THR, "%s@%d-%p: FROM %s@%d:: Getting callback mutex lock\n",
      __FILE__, __LINE__, PPTID, whom, from_line);
  rc = pthread_mutex_lock(&psi_callback_mutext);
  hold_errno = errno;
  DBG(DBG_THR, "%s@%d-%p: FROM %s@%d:: lock-attempt result was %d\n",
      __FILE__, __LINE__, PPTID, whom, from_line, rc);
  if (rc < 0) {
      fprintf(stderr, "%s@%d-%p: FROM %s@%d:: mutex lock failed. rc=%d, errno=%d(%s)\n",
	      __FILE__, __LINE__, PPTID, whom, from_line, rc, hold_errno, strerror(hold_errno));
      abort();
  }
}

static void
psi_callback_unlock(const char *whom, uint32_t from_line) {
  int rc;
  int hold_errno;
  
  DBG(DBG_THR, "%s@%d-%p: FROM %s@%d:: Releasing callback mutex lock\n",
      __FILE__, __LINE__, PPTID, whom, from_line);
  rc = pthread_mutex_unlock(&psi_callback_mutext);
  hold_errno = errno;
  DBG(DBG_THR, "%s@%d-%p: FROM %s@%d:: unlock-attempt result was %d\n",
      __FILE__, __LINE__, PPTID, whom, from_line, rc);
  if (rc < 0) {
      fprintf(stderr, "%s@%d-%p: FROM %s@%d:: mutex unlock failed. rc=%d, errno=%d(%s)\n",
	      __FILE__, __LINE__, PPTID, whom, from_line, rc, hold_errno, strerror(hold_errno));
      abort();
  }
}

#define PSI_CALLBACK_LOCK()      (psi_callback_lock(__func__, __LINE__))
#define PSI_CALLBACK_UNLOCK()    (psi_callback_unlock(__func__, __LINE__))

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

  DBG(DBG_PSI, "%s@%d-%p: python is available for python based active simulation.\n", __FILE__, __LINE__, PPTID);

  psi_simulator_dot_py = getenv("UMOCKDEV_PYTHON_SIMULATOR");
  if (psi_simulator_dot_py == NULL) {
    DBG(DBG_PSI, "%s@%d-%p: UMOCKDEV_PYTHON_SIMULATOR env not defined. Not activating python.\n", __FILE__, __LINE__, PPTID);
  } else {
    DBG(DBG_PSI, "%s@%d-%p: UMOCKDEV_PYTHON_SIMULATOR is '%s'. Activating python.\n", __FILE__, __LINE__, PPTID, psi_simulator_dot_py);

    /* Add a built-in module, before Py_Initialize */
    PyImport_AppendInittab("umockdev_preload", PyInit_umockdev_module);
    
    /* TODO: Py_SetProgramName((wchar_t *)python_prog_name);  optional but recommended */
    Py_Initialize();

    
    sfile = fopen(psi_simulator_dot_py, "r");
    if (sfile == NULL) {
      DBG(DBG_PSI, "%s@%d-%p: Unable to open '%s' to run in python because %d(%s). Simulator unavailable.\n",
	  __FILE__, __LINE__, PPTID, psi_simulator_dot_py, errno, strerror(errno));
      /* TODOQ: should this abort instead? */
    } else {
      DBG(DBG_PSI, "%s@%d-%p: executing '%s'...\n", __FILE__, __LINE__, PPTID, psi_simulator_dot_py);
      if (PyRun_AnyFile(sfile, psi_simulator_dot_py)) {
	/* note, if the run failed, stuff will haev printed on stderr about why. */
	DBG(DBG_PSI, "%s@%d-%p:   --run failed! see preceeding backtrace--\n", __FILE__, __LINE__, PPTID);
	abort();
      }
      DBG(DBG_PSI, "%s@%d-%p: python-simulator has been run and is active.\n", __FILE__, __LINE__, PPTID);
      fclose(sfile);
    }
  }
}

void
psim_destructor(void) {
  DBG(DBG_PSI, "%s@%d-%p: psim_destructor called.\n", __FILE__, __LINE__, PPTID);
  /* TODOQ: clean up callbacks. */
}

int
psim_i2c_rdwr_execute_cb(const char *dev, IOCTL_REQUEST_TYPE id, struct i2c_rdwr_ioctl_data *rdwr_req, int *ret) {
  psi_i2c_callback_td *our_cb;
  PyObject *arglist, *result;
  struct i2c_msg *a_msg;
  uint16_t found_addr = 0;
  size_t msg_n;
  int new_errno;

  if (rdwr_req->nmsgs == 0) {
    DBG(DBG_PSI, "%s@%d-%p: can't match without any contained messages.\n", __FILE__, __LINE__, PPTID);
    return 0;
  }

  found_addr = rdwr_req->msgs[0].addr;
  for (msg_n = 0; msg_n < rdwr_req->nmsgs; msg_n++) {
    a_msg = &rdwr_req->msgs[msg_n];
    if (a_msg->addr != found_addr) {
      DBG(DBG_PSI, "%s@%d-%p: i2c_rdwr_ioctl had multiple addresses in it (0x%04x 0x%04x). Skipping\n",
	  __FILE__, __LINE__, PPTID, found_addr, a_msg->addr);
      return 0;
    }
  }

  our_cb = psi_i2c_callback_find(dev, found_addr);
  if (our_cb == NULL) {
    DBG(DBG_PSI, "%s@%d-%p: did not find %s(0x%04x) in callbacks\n", __FILE__, __LINE__, PPTID, dev, found_addr);
    return 0;
  }

  PSI_CALLBACK_LOCK();
  
  //  msgs_as_char_ptr = (const char *)&rdwr_req->msgs[0];
  //msgs_size = sizeof(struct i2c_msg) * rdwr_req->nmsgs;
  arglist = Py_BuildValue("(skIk)", dev, id, found_addr, rdwr_req);
  DBG(DBG_PSI, "%s@%d-%p: going to call callback for %s(0x%04x), rdwr_req=%p\n",
      __FILE__, __LINE__, PPTID, dev, found_addr, rdwr_req);
  result = PyObject_CallObject(our_cb->psic_callback, arglist);
  if (result == NULL) {
    PyErr_PrintEx(0);
    PSI_CALLBACK_UNLOCK();
    abort();
  } else {
    if (!PyArg_ParseTuple(result, "ii", ret, &new_errno)) {
      PyErr_PrintEx(0);
      PSI_CALLBACK_UNLOCK();
      abort();
    }
  }
      
  DBG(DBG_PSI, "%s@%d-%p: DONE with callback for %s(0x%04x), ret=%d, errno=%d\n",
      __FILE__, __LINE__, PPTID, dev, found_addr, *ret, new_errno);
  Py_DECREF(arglist);
  PSI_CALLBACK_UNLOCK();

  errno = new_errno;
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
  PyObject *arglist, *result;
  unsigned long dir, mtype, nr, bsize;
  int handled;
  int ret_errno = 0;

  our_cb = psi_simplestruct_ioctl_callback_find(dev, id);
  if (our_cb == NULL) {
    DBG(DBG_PSI, "%s@%d-%p: did not find %s(0x%08lx) in callbacks\n", __FILE__, __LINE__, PPTID, dev, id);
    return 0;
  }
  dir = _IOC_DIR(id);
  mtype = _IOC_TYPE(id);
  nr = _IOC_TYPE(id);
  bsize = _IOC_SIZE(id);
  
  DBG(DBG_PSI, "%s@%d-%p: going to CB for %s(0x%08lx->dir=0x%lx, mtype=0x%lx, nr=0x%lx, size=%lu)\n",
      __FILE__, __LINE__, PPTID, dev, id, dir, mtype, nr, bsize);
  DBG(DBG_PSI, "%s@%d-%p:   f_ret=%p(->%d). errno=%p(->%d)\n", __FILE__, __LINE__, PPTID, ret, *ret, &ret_errno,
      ret_errno);
  arglist = Py_BuildValue("(skIIIIk)", dev, id, dir, mtype, nr, bsize, arg);
  assert(arglist != NULL);
  result = PyObject_CallObject(our_cb->psisc_callback, arglist);
  handled = 0;
  if (result == NULL) {
    PyErr_PrintEx(0);
    abort();   /* for now at least */
  } else {
    if (!PyArg_ParseTuple(result, "pii", &handled, ret, &ret_errno)) {
      PyErr_PrintEx(0);
      abort();
    }
  }
  Py_DECREF(arglist);
  if (!handled) {
    DBG(DBG_PSI, "%s@%d-%p: callback returned for %s(0x%08lx): passed on handling ioctl\n",
	__FILE__, __LINE__, PPTID, dev, id);
  } else {
    DBG(DBG_PSI, "%s@%d-%p: callback returned for %s(0x%08lx): will yield function_return=%d, errno-will-be=%d\n",
	__FILE__, __LINE__, PPTID, dev, id, *ret, ret_errno);
    errno = ret_errno;
  }
  /* TODO: deref result?!?!? (here OR psim_i2c_rdwr_execute_cb) */
  return handled;
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

  
psimi_generic_file_td *
psim_generic_file_open(const char *dev_path) {
  psimi_generic_file_td *handler;

  handler = psi_generic_file_handle_find(dev_path);
  DBG(DBG_GF, "%s@%d-%p: generic file open for %s. Handler was %p\n", __FILE__, __LINE__, PPTID, dev_path,
      handler);
  return handler;
}

void
psim_generic_file_close(psimi_generic_file_td *psim_generic_file_handle) {
}

ssize_t
psim_generic_file_write(psimi_generic_file_td *psim_generic_file_handle, const void *buf, size_t count) {
  PyObject *arglist, *result;
  int new_errno;
  size_t ret;

  PSI_CALLBACK_LOCK();

  arglist = Py_BuildValue("(sny#)", "write", count, buf, count);

  DBG(DBG_GF, "%s@%d-%p: going file write, count=%d\n", __FILE__, __LINE__, PPTID, count);
  result = PyObject_CallObject(psim_generic_file_handle->psigf_callback, arglist);
  if (result == NULL) {
    PyErr_PrintEx(0);
    PSI_CALLBACK_UNLOCK();
    abort();
  } else {
    if (!PyArg_ParseTuple(result, "ni", &ret, &new_errno)) {
      PyErr_PrintEx(0);
      PSI_CALLBACK_UNLOCK();
      abort();
    }
  }
      
  DBG(DBG_GF, "%s@%d-%p: DONE write callback, ret=%d, errno=%d\n",
      __FILE__, __LINE__, PPTID, ret, new_errno);
  Py_DECREF(arglist);
  PSI_CALLBACK_UNLOCK();

  errno = new_errno;
  return ret;
}

ssize_t
psim_generic_file_read(psimi_generic_file_td *psim_generic_file_handle, const void *buf, size_t count) {
  PyObject *arglist, *result;
  int new_errno;
  size_t ret;

  PSI_CALLBACK_LOCK();

  arglist = Py_BuildValue("(snk)", "read", count, buf);

  DBG(DBG_GF, "%s@%d-%p: going read write, count=%d, bufaddr=%p\n", __FILE__, __LINE__, PPTID, count, buf);
  result = PyObject_CallObject(psim_generic_file_handle->psigf_callback, arglist);
  if (result == NULL) {
    PyErr_PrintEx(0);
    PSI_CALLBACK_UNLOCK();
    abort();
  } else {
    if (!PyArg_ParseTuple(result, "ni", &ret, &new_errno)) {
      PyErr_PrintEx(0);
      PSI_CALLBACK_UNLOCK();
      abort();
    }
  }
      
  DBG(DBG_GF, "%s@%d-%p: DONE read callback, ret=%d, errno=%d\n",
      __FILE__, __LINE__, PPTID, ret, new_errno);
  Py_DECREF(arglist);
  PSI_CALLBACK_UNLOCK();

  errno = new_errno;
  return ret;
}

