#include "include/shm_ringbuf.h"
#include <stdio.h>

#define MIN(a, b) ((a > b) ? b : a)
#define MAX(a, b) ((a > b) ? a : b)

static inline int shm_cleanup(union shmrbuf_arg_t *args, enum shmrbuf_role_t role, bool detach) {

  int retval = IO_IPC_SUCCESS, shm_id;
  uint32_t size;
  void *global_hdr, *segment_hdrs;
  struct shmid_ds shmid_ds;

  switch (role) {
  case SHMRBUF_READER:

    size = sizeof(struct shmrbuf_reader_arg_t);
    global_hdr = (void *)args->rargs.global_hdr;
    segment_hdrs = (void *)args->rargs.segment_hdrs;
    shm_id = args->rargs.shm_id;

    break;

  case SHMRBUF_WRITER:

    size = sizeof(struct shmrbuf_writer_arg_t);
    global_hdr = (void *)args->wargs.global_hdr;
    segment_hdrs = (void *)args->wargs.segment_hdrs;
    shm_id = args->wargs.shm_id;

    break;

  default:
    return IO_IPC_ARG_ERR;
  }

  if (detach) {
    if (shmdt(global_hdr) == -1) {
      retval = errno;
    }

    else if (shmctl(shm_id, IPC_STAT, &shmid_ds) == -1) {
      retval = errno;
    }

    else if (shmid_ds.shm_nattch == 0) {
      if (shmctl(shm_id, IPC_RMID, NULL) == -1) {
        retval = errno;
      }
    }
  }

  free(segment_hdrs);
  memset(args, 0, size);

  return retval;
}

static inline uint32_t get_hdr_checksum(struct shmrbuf_global_hdr_t *global_hdr, key_t key) {
  return (key + global_hdr->line_count + global_hdr->line_size +
          global_hdr->overwrite + global_hdr->reader_count +
          global_hdr->segment_count) %
         UINT32_MAX;
}

int shmrbuf_init(union shmrbuf_arg_t *args, enum shmrbuf_role_t role) {
  // error if struct of arguments is empty/NULL
  if (args == NULL) {
    return IO_IPC_NULLPTR_ERR;
  }

  bool reattach = false, overwrite = false, exists = false, force = false,
       reset = false;
  int shm_id, shm_flags = 0, retval, i;
  key_t key = -1;
  off_t size = 0;
  struct shmrbuf_global_hdr_t *global_hdr;
  struct shmrbuf_seg_hdr_t *segment_hdrs;

  switch (role) {
  case SHMRBUF_WRITER:

    reattach = (args->wargs.flags & SHMRBUF_REATT);
    overwrite = (args->wargs.flags & SHMRBUF_OVWR);
    force = (args->wargs.flags & SHMRBUF_FRCAT);

    if (args->wargs.shm_key == NULL ||
        !reattach &
            (args->wargs.line_size == 0 || args->wargs.line_count == 0 ||
             args->wargs.segment_count == 0 || args->wargs.reader_count == 0)) {
      return IO_IPC_ARG_ERR;
    }

    shm_flags = IPC_EXCL | IPC_CREAT | SHMRBUF_PERM;

    key = ftok(args->wargs.shm_key,
               0); // calculates key for System V shared memory api
    size = sizeof(struct shmrbuf_global_hdr_t) +
           (args->wargs.reader_count - 1) * sizeof(atomic_bool) +
           args->wargs.segment_count *
               (args->wargs.line_count * args->wargs.line_size +
                (args->wargs.reader_count + 1) * sizeof(atomic_uint_fast32_t));

    break;

  case SHMRBUF_READER:

    if (args->rargs.shm_key == NULL) {
      return IO_IPC_ARG_ERR;
    }

    reset = args->rargs.flags & SHMRBUF_RESET;

    key = ftok(args->rargs.shm_key, 0);

    break;

  default:
    return IO_IPC_ARG_ERR;
  }

  if (key == -1) {
    return errno;
  }

  // Try to attach to existing segment
  if (role == SHMRBUF_READER || reattach) {
    if ((shm_id = shmget(key, 0, 0)) == -1) {
      if (role == SHMRBUF_READER) {
        return errno;
      }
      exists = false;
    } else {
      exists = true;
    }
  }

  // Create new segment (writer only)
  if (!exists &&
      role == SHMRBUF_WRITER) // role check is redundant but doppelt hält besser
  {

    if (size > PAGESIZE) {
      // If the required size is larger than one page, try to allocate huge
      // pages
      shm_id = shmget(key, size, shm_flags | SHM_HUGETLB);
    }

    // Try again if allocation with SHM_HUGETLB failed
    if (size <= PAGESIZE || shm_id == -1) {
      if ((shm_id = shmget(key, size, shm_flags)) == -1) {
        return errno;
      }
    }
  }

  if ((global_hdr = (struct shmrbuf_global_hdr_t *)shmat(shm_id, NULL, 0)) ==
      (void *)-1) {
    retval = errno;
    shm_cleanup(args, role, false);
    return retval;
  }

  if (role == SHMRBUF_WRITER) {

    if (exists) {
      if (global_hdr->checksum != get_hdr_checksum(global_hdr, key) ||
          (global_hdr->writer_att == true && !force)) {
        shm_cleanup(args, role, true);
        return IO_IPC_ARG_ERR;
      }

      global_hdr->writer_att = true;
    } else {
      global_hdr->line_count = args->wargs.line_count;
      global_hdr->line_size = args->wargs.line_size;
      global_hdr->segment_count = args->wargs.segment_count;
      global_hdr->reader_count = args->wargs.reader_count;
      global_hdr->overwrite = overwrite;
      global_hdr->checksum = get_hdr_checksum(global_hdr, key);
      global_hdr->writer_att = true;
      
      memset(&global_hdr->first_reader_att, 0,
             sizeof(atomic_bool) * global_hdr->reader_count);
    }

    args->wargs.global_hdr = global_hdr;
    args->wargs.shm_id = shm_id;

    // TODO change function parameters -> calloc(num_element, sizeof_element)
    if ((args->wargs.segment_hdrs = (struct shmrbuf_seg_whdr_t *)calloc(
             sizeof(struct shmrbuf_seg_whdr_t), global_hdr->segment_count)) ==
        NULL) {
      shm_cleanup(args, role, exists);
      return IO_IPC_MEM_ERR;
    }

  }

  else {

    if (global_hdr->checksum != get_hdr_checksum(global_hdr, key) ||
        global_hdr->segment_count == 0 || global_hdr->line_count == 0 ||
        global_hdr->line_size == 0) {
      shm_cleanup(args, role, true);
      return IO_IPC_ARG_ERR;
    }

    args->rargs.global_hdr = global_hdr;
    args->rargs.shm_id = shm_id;

    if (!(args->rargs.flags & SHMRBUF_NOREG)) {
      bool registered = false;
      for (i = 0; i < global_hdr->reader_count; i++) {
        if (atomic_compare_exchange_strong((&global_hdr->first_reader_att + i),
                                           &registered, true)) {
          args->rargs.reader_id = i;
          registered = true;
          break;
        }
        registered = false;
      }

      if (!registered) {
        shm_cleanup(args, role, true);
        return IO_IPC_SIZE_ERR;
      }
    }
    // TODO change function parameters -> calloc(num_element, sizeof_element)
    if ((args->rargs.segment_hdrs = (struct shmrbuf_seg_rhdr_t *)calloc(
             sizeof(struct shmrbuf_seg_rhdr_t), global_hdr->segment_count)) ==
        NULL) {
      shm_cleanup(args, role, true);
      return IO_IPC_MEM_ERR;
    }
  }

  size_t offset = sizeof(struct shmrbuf_global_hdr_t) +
                  (global_hdr->reader_count - 1) * sizeof(atomic_bool),
         segment_size =
             sizeof(atomic_uint_fast32_t) * (global_hdr->reader_count + 1) +
             global_hdr->line_size * global_hdr->line_count;

  for (int i = 0; i < global_hdr->segment_count; i++) {

    atomic_uint_fast32_t *seg_head =
        (atomic_uint_fast32_t *)((char *)global_hdr + offset);

    if (role == SHMRBUF_WRITER) {

      struct shmrbuf_seg_whdr_t *seg_whdr = &args->wargs.segment_hdrs[i];

      seg_whdr->write_index = seg_head;
      seg_whdr->first_reader = seg_head + 1;
      seg_whdr->data = (void *)(seg_head + 1 + global_hdr->reader_count);

      if (!exists) {
        // Zero out write and read indices when creating segment
        memset(seg_head, 0,
               (1 + global_hdr->reader_count) * sizeof(atomic_uint_fast32_t));
      }

    }

    else {

      struct shmrbuf_seg_rhdr_t *seg_rhdr = &args->rargs.segment_hdrs[i];

      seg_rhdr->write_index = seg_head;
      seg_rhdr->read_index = seg_head + (args->rargs.reader_id + 1);
      seg_rhdr->data = (void *)(seg_head + global_hdr->reader_count + 1);

      if (reset) {
        uint32_t write_index = atomic_load(seg_rhdr->write_index);
        if (write_index != *seg_rhdr->read_index) {
          atomic_store(seg_rhdr->read_index, write_index);
        }
      }
    }

    offset += segment_size;
  }

  return IO_IPC_SUCCESS;
}

int shmrbuf_finalize(union shmrbuf_arg_t *args, enum shmrbuf_role_t role) {

  if (args == NULL) {
    return IO_IPC_NULLPTR_ERR;
  }

  bool destroy = false;

  switch (role) {
  case SHMRBUF_WRITER:

    args->wargs.global_hdr->writer_att = false;

    break;

  case SHMRBUF_READER:

    if (!(args->rargs.flags & SHMRBUF_NOREG)) {
      *(&args->rargs.global_hdr->first_reader_att + args->rargs.reader_id) =
          false;
    }

  default:
    break;
  }

  return shm_cleanup(args, role, true);
}

inline int shmrbuf_write(struct shmrbuf_writer_arg_t *args, void *src,
                         uint16_t wsize, uint8_t segment_id) {

  // check on empty arguments
  if (args == NULL || src == NULL || args->segment_hdrs == NULL) {
    return IO_IPC_NULLPTR_ERR;
  }

  struct shmrbuf_global_hdr_t *global_hdr = args->global_hdr;

  // check if segment_id and size of input is within valid range
  if (segment_id >= global_hdr->segment_count ||
      wsize > global_hdr->line_size) {
    return IO_IPC_ARG_ERR;
  }

  if (wsize == 0) {
    return wsize;
  }

  // extract parameters for synchronization of chosen segment
  struct shmrbuf_seg_whdr_t *segment = &args->segment_hdrs[segment_id];
  uint32_t write_index = atomic_load(segment->write_index);
  uint32_t new_write_index =
      (write_index == global_hdr->line_count - 1) ? 0 : write_index + 1;
  uint16_t line_size = global_hdr->line_size;
  // start point of writing operation (writing starts always in "new" line of
  // ringbuffer)
  char *write_dest = ((char *)segment->data + write_index * line_size);

  if (!global_hdr->overwrite) {
    // check if writer overtakes reader(s)
    // while overwriting is not allowed terminate with error
    for (int i = 0; i < global_hdr->reader_count; i++) {
      if (new_write_index == atomic_load(segment->first_reader + i)) {
        return IO_IPC_SIZE_ERR;
      }
    }
  }

  if (memcpy(write_dest, src, wsize) == NULL) {
    return IO_IPC_MEM_ERR;
  }
  // fill up all unused space in the ringbuffer line with '\0'
  while (wsize < line_size) {
    *(write_dest + wsize++) = '\0';
  }

  atomic_store(segment->write_index, new_write_index);

  return wsize;
}

inline int shmrbuf_read(struct shmrbuf_reader_arg_t *args, void *rbuf,
                        uint16_t bufsize, uint8_t segment_id) {

  if (args == NULL || rbuf == NULL || args->segment_hdrs == NULL) {
    return IO_IPC_NULLPTR_ERR;
  }

  struct shmrbuf_global_hdr_t *global_hdr = args->global_hdr;

  if (segment_id >= global_hdr->segment_count) {
    return IO_IPC_ARG_ERR;
  }

  if (bufsize == 0) {
    return bufsize;
  }
  // extract parameters for synchronization of chosen segment
  struct shmrbuf_seg_rhdr_t *segment = &args->segment_hdrs[segment_id];
  uint32_t write_index = atomic_load(segment->write_index);
  uint16_t line_size = global_hdr->line_size;

  // Read process is multithreaded, so accesses to synchronisation variables
  // must be coordinated
  if (pthread_mutex_lock(&segment->segment_lock) == -1) {
    return IO_IPC_MUTEX_ERR;
  }

  uint32_t read_index = *segment->read_index;
  uint32_t new_read_index =
      (read_index == global_hdr->line_count - 1) ? 0 : read_index + 1;
  // at most line_size elements can be read
  uint16_t rsize = MIN(line_size, bufsize);

  // if the read and write indexes have the same value, there is nothing to read
  // so that the function can be terminated
  if (write_index == read_index) {
    if (pthread_mutex_unlock(&segment->segment_lock) == -1) {
      return IO_IPC_MUTEX_ERR;
    }

    return 0;
  }

  if (memcpy(rbuf, (char *)segment->data + read_index * line_size, rsize) ==
      NULL) {
    return IO_IPC_MEM_ERR;
  }
  // save new index in synchronization struct
  atomic_store(segment->read_index, new_read_index);

  if (pthread_mutex_unlock(&segment->segment_lock) == -1) {
    return IO_IPC_MUTEX_ERR;
  }

  return rsize;
}

int shmrbuf_writev(struct shmrbuf_writer_arg_t *args, struct iovec *iovecs,
                   uint16_t vsize, uint8_t segment_id) {
  if (args == NULL || iovecs == NULL || args->segment_hdrs == NULL) {
    return IO_IPC_NULLPTR_ERR;
  }

  else if (segment_id >= args->segment_count) {
    return IO_IPC_ARG_ERR;
  }

  if (vsize == 0) {
    return vsize;
  }

  struct shmrbuf_seg_whdr_t *segment = &args->segment_hdrs[segment_id];
  struct shmrbuf_global_hdr_t *global_hdr = args->global_hdr;
  uint16_t line_size = global_hdr->line_size;
  bool overwrite = global_hdr->overwrite;
  uint32_t write_index = *segment->write_index,
           line_count = global_hdr->line_count;
  char *write_dest = ((char *)segment->data + write_index * line_size);
  // if number of iovec lines is higher than the number of lines in
  // ringbuffer, than write only line_count elements in buffer segment
  vsize = (vsize > line_count) ? line_count : vsize;

  if (!overwrite) {

    uint32_t read_index, dst;

    for (int i = 0; i < global_hdr->reader_count; i++) {
      read_index = atomic_load(segment->first_reader + i);
      // check distance between writer and every reader id
      // adapt distance (dst) variable so that only space between writer and
      // reader is filled but not beyond that (overwriting is avoided)
      dst = (read_index > write_index)
                ? read_index - write_index - 1
                : line_count - (write_index - read_index) - 1;
      // number of line elements is reduced if overwriting would occur
      vsize = (dst < vsize) ? dst : vsize;

      if (vsize == 0) {
        return 0;
      }
    }
  }

  // new write index is determined with modulo operation because of the
  // ringbuffer architecture
  uint32_t new_write_index = (write_index + vsize) % line_count;

  // if write process ends before the end of the ring buffer cycle, all
  // elements can be written to the buffer directly
  if (new_write_index > write_index) {

    for (uint16_t i = 0; i < vsize; i++) {
      uint16_t wsize = iovecs[i].iov_len;

      if (wsize > line_size) {
        return IO_IPC_SIZE_ERR;
      }
      
      if (memcpy(write_dest, iovecs[i].iov_base, wsize) == NULL) {
        return IO_IPC_MEM_ERR;
      }
      // fill up all unused space in the ringbuffer line with '\0'
      while (wsize < line_size) {
        *(write_dest + wsize) = '\0';
        wsize++;
      }

      write_dest += line_size;
    }

  }

  // if the write process ends in the new ring buffer cycle, a buffer cycle is
  // ended first and the remaining elements are written to a new buffer cycle.
  else {
    uint16_t dst = line_count - write_index, i;

    for (i = 0; i < dst; i++) {
      uint16_t wsize = iovecs[i].iov_len;

      if (wsize > line_size) {
        return IO_IPC_SIZE_ERR;
      }

      if (memcpy(write_dest, iovecs[i].iov_base, wsize) == NULL) {
        return IO_IPC_MEM_ERR;
      }

      // fill up all unused space in the ringbuffer line with '\0'
      while (wsize < line_size) {
        *(write_dest + wsize) = '\0';
        wsize++;
      }

      write_dest += line_size;
    }

    // write the remaining lines to the new ring buffer cycle
    dst = vsize - dst;
    write_dest = (char *)segment->data;

    for (i = 0; i < dst; i++) {
      uint16_t wsize = iovecs[i].iov_len;

      if (wsize > line_size) {
        return IO_IPC_SIZE_ERR;
      }

      if (memcpy(write_dest, iovecs[i].iov_base, wsize) == NULL) {
        return IO_IPC_MEM_ERR;
      }

      while (wsize < line_size) {
        *(write_dest + wsize) = '\0';
        wsize++;
      }

      write_dest += line_size;
    }
  }

  atomic_store(segment->write_index, new_write_index);
  // fprintf(stderr, "vsize: %d\n", vsize);
  return vsize;
}

int shmrbuf_readv(struct shmrbuf_reader_arg_t *args, struct iovec *iovecs,
                  uint16_t vsize, uint16_t bufsize, uint8_t segment_id) {
  if (args == NULL || iovecs == NULL || args->segment_hdrs == NULL) {
    return IO_IPC_NULLPTR_ERR;
  }

  struct shmrbuf_global_hdr_t *global_hdr = args->global_hdr;

  if (segment_id >= global_hdr->segment_count) {
    return IO_IPC_ARG_ERR;
  }

  if (vsize == 0) {
    return vsize;
  }

  struct shmrbuf_seg_rhdr_t *segment = &args->segment_hdrs[segment_id];
  uint32_t write_index = atomic_load(segment->write_index);

  if (pthread_mutex_lock(&segment->segment_lock) == -1) {
    return IO_IPC_MUTEX_ERR;
  }
              
  uint32_t read_index = *segment->read_index;

  if (write_index == read_index) {
    // locking of synchronisation as the read process is multithreaded
    if (pthread_mutex_unlock(&segment->segment_lock) == -1) {
      return IO_IPC_MUTEX_ERR;
    }

    return 0;
  }

  uint32_t line_count = global_hdr->line_count;
  uint16_t line_size = global_hdr->line_size;
  // determination of the maximum number of elements to be read in. If the
  // reader is before the writer, the writer is already in a new ring cycle,
  // so that all elements of the ring cycle are read in from the reader and
  // the new cycle up to the writer. If the reader is behind the writer, both
  // are in the same cycle and only the elements up to the writer need to be
  // read in.
  uint32_t max_read = (read_index > write_index)
                          ? line_count - (read_index - write_index)
                          : (write_index - read_index);
  // The number of lines in the vector structure is limited to the maximum
  // number of lines to be read in the ring buffer
  vsize = (vsize > max_read) ? max_read : vsize;
  uint32_t new_read_index = (read_index + vsize) % line_count;
  char *src = (char *)segment->data + read_index * line_size;
  struct iovec *iov;

  if (bufsize < line_size) {
    pthread_mutex_unlock(&segment->segment_lock);
    return IO_IPC_SIZE_ERR;
  }

  // elements from the shared memory are written line by line into the iovec
  // vector structure
  for (uint16_t i = 0; i < vsize; i++) {
    iov = &iovecs[i];
    if (memcpy(iov->iov_base, src, line_size) == NULL) {
      pthread_mutex_unlock(&segment->segment_lock);
      return IO_IPC_MEM_ERR;
    }
    iov->iov_len = line_size;
    src += line_size;
  }

  // updating the read index and unlocking the synchronisation structure
  atomic_store(segment->read_index, new_read_index);

  if (pthread_mutex_unlock(&segment->segment_lock) == -1) {
    return IO_IPC_MUTEX_ERR;
  }

  return vsize;
}

int shmrbuf_read_rng(struct shmrbuf_reader_arg_t *args, void *rbuf,
                     uint16_t bufsize, uint8_t lower, uint8_t upper,
                     bool *wsteal) {
  static thread_local uint8_t segment_index = 0;
  static thread_local uint8_t steal_index = 0;
  uint8_t i, rng = upper - lower,
             segment_count = args->global_hdr->segment_count;
  int retval;

  if (lower > upper || upper > segment_count) {
    return IO_IPC_ARG_ERR;
  }

  for (i = 0; i < rng; i++) {
    if (segment_index == upper) {
      segment_index = lower;
    } else if (segment_index < lower) {
      segment_index = lower;
    }

    if ((retval = shmrbuf_read(args, rbuf, bufsize, segment_index++)) < 0) {
      return retval;
    }

    else if (retval > 0) {
      return retval;
    }
  }

  if (wsteal != NULL) {
    uint8_t steal_rng = segment_count - rng;

    for (i = 0; i < steal_rng; i++) {
      // index of steal_index is coordinated so that it always iterates over
      // the other segments outside the [lower, upper] range using the
      // roundrobin method
      if (steal_index == lower) {
        steal_index = (upper == segment_count) ? 0 : upper;
      } else if (steal_index == segment_count) {
        steal_index = (lower == 0) ? upper : 0;
      }
      // return error message of reading process failed
      if ((retval = shmrbuf_read(args, rbuf, bufsize, steal_index++)) < 0) {
        return retval;
      }
      // if reading process is succesful reaturn number of elements read
      else if (retval > 0) {
        *wsteal = true;
        return retval;
      }
    }
  }

  return 0;
}

// same procedure as in shrmbuf_read_rng but using shrmbuf_readv function
int shmrbuf_readv_rng(struct shmrbuf_reader_arg_t *args, struct iovec *iovecs,
                      uint16_t vsize, uint16_t bufsize, uint8_t lower,
                      uint8_t upper, uint16_t *wsteal) {
  static thread_local uint8_t segment_index = 0;
  static thread_local uint8_t steal_index = 0;
  uint8_t i, rng = upper - lower,
             segment_count = args->global_hdr->segment_count;
  uint16_t read = 0;
  int retval;

  if (lower > upper || upper > segment_count) {
    return IO_IPC_ARG_ERR;
  }

  for (i = 0; i < rng; i++) {
    if (segment_index == upper) {
      segment_index = lower;
    } else if (segment_index < lower) {
      segment_index = lower;
    }

    if ((retval = shmrbuf_readv(args, &iovecs[read], vsize, bufsize,
                                segment_index++)) < 0) {
      return retval;
    }

    else if (retval > 0) {
      read += retval;
      if (retval == vsize) {
        return read;
      }
      vsize -= retval;
    }
  }

  if (wsteal != NULL) {
    uint8_t steal_rng = segment_count - rng;

    for (i = 0; i < steal_rng; i++) {

      if (steal_index == lower) {
        steal_index = (upper == segment_count) ? 0 : upper;
      } else if (steal_index == segment_count) {
        steal_index = (lower == 0) ? upper : 0;
      }

      if ((retval = shmrbuf_readv(args, &iovecs[read], vsize, bufsize,
                                  steal_index++)) < 0) {
        return retval;
      }

      else if (retval > 0) {
        read += retval;
        *wsteal += retval;
        if (retval == vsize) {
          return read;
        }
        vsize -= retval;
      }
    }
  }

  return read;
}
