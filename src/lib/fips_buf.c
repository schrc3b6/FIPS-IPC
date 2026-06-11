#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <fips_buf.h>
#include <linux/limits.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <linux/shm.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <libgen.h>
#include <libconfig.h>


// Layout of the shared memory buffer
// because we want to make it flexible to add writers and readers at runtime we
// adopt the following layout
// 1.1. header
// 1.2. writer assignments
// 1.3. reader assignments
// 2.1. segment_header
// 2.2. reader lists
// 2.3. segment_data
// 3.1. segment_header
// 3.2. reader lists
// 3.3. segment_data
// ...

size_t calculate_shared_memory_size(fips_buf_arg_t *arg) {
  // calculate addresses and defere size from that
  size_t size =
      (sizeof(fips_buf_header_t) +
       ((arg->max_segment_count + 7)&~7) * sizeof(uint8_t) + // writers in segment_assignment for alignment reason always allocate a multiplicative of 64bit
       arg->max_reader_count * arg->max_reader_thread_count *
           sizeof(fips_buf_assignment_t) +      // readers in segment_assignment
       arg->max_segment_count *                 // memory for each segment
           (sizeof(fips_buf_segment_header_t) + // segment_header
            arg->max_reader_count *
                (sizeof(fips_buf_pointer_t) + // pointers of readers
                 sizeof(fips_buf_list_t) +    // list structure to handle sqe's
                 sizeof(fips_buf_sqe_t) *
                     arg->max_sqe_count) + // sqe list of readers
            (1 << arg->line_count_exp) *
                (arg->line_size + LINE_WIDTH_SIZE))); // segment_data

#ifdef DEBUG
  fprintf(stderr, "size: %ld\n", size);
  fflush(stderr);
#endif
  return size;
}

uint64_t calc_checksum(fips_buf_arg_t *arg) {
  if (strlen(arg->shm_name) > 7) {
    return ((*(uint64_t *)arg->shm_name) ^
            ((uint64_t)arg->line_count_exp |
             ((uint64_t)arg->max_reader_count << 8) |
             ((uint64_t)arg->max_reader_thread_count << 16) |
             ((uint64_t)arg->max_segment_count << 24) |
             ((uint64_t)arg->line_size << 32)) ^
            arg->max_sqe_count);
  } else {
    return (((uint64_t)arg->line_count_exp |
             ((uint64_t)arg->max_reader_count << 8) |
             ((uint64_t)arg->max_reader_thread_count << 16) |
             ((uint64_t)arg->max_segment_count << 24) |
             ((uint64_t)arg->line_size << 32)) ^
            arg->max_sqe_count);
  }
}

int checksum(fips_buf_arg_t *arg) {

  if (calc_checksum(arg) == arg->header->checksum)
    return 0;
  return 1;
}

int setup_shm(fips_buf_arg_t *arg) {
  if (arg->header->initialized != 0) {
    return 0;
  }
  fips_buf_header_t *header = arg->header;
  header->line_size = arg->line_size;
  header->line_count_exp = arg->line_count_exp;
  header->line_MASK = (1 << arg->line_count_exp) - 1;
  header->max_reader_count = arg->max_reader_count;
  header->max_reader_thread_count = arg->max_reader_thread_count;
  header->segment_count = arg->max_segment_count;
  header->max_sqe_count = arg->max_sqe_count;
  header->flags = arg->flags;

  // initialize assignment_lock
  pthread_mutexattr_t mutex_attr;
  pthread_mutexattr_init(&mutex_attr);
  pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
  pthread_mutex_init(&header->assignment_lock, &mutex_attr);
  // printf("assignment_lock: %p \n", &header->assignment_lock);
  header->checksum = calc_checksum(arg);

  header->writer_assignments_offset = GET_POINTER_OFFSET(header, header + 1);
  header->reader_assignments_offset =
      (header->writer_assignments_offset + ((arg->max_segment_count + 7)&~7));
  header->first_segment_offset =
      (header->reader_assignments_offset +
       (arg->max_reader_count * arg->max_reader_thread_count *
        sizeof(fips_buf_assignment_t)));
  // header->first_segment->prev = NULL;

  fips_buf_segment_header_t *current_segment =
      APPLY_POINTER_OFFSET(header, header->first_segment_offset);
  for (int i = 0; i < arg->max_segment_count; i++) {
    current_segment->readers_offset =
        GET_POINTER_OFFSET(header, current_segment + 1);
    for (int j = 0; j < arg->max_reader_count; j++) {
      pthread_mutex_init(
          &(((fips_buf_list_t *)APPLY_POINTER_OFFSET(
                 header, FIPS_BUF_GET_READER_SGE_LIST(
                             header, current_segment->readers_offset, j)))
                ->lock),
          &mutex_attr);
      // printf("sge list lock %p\n", &(((fips_buf_list_t *)APPLY_POINTER_OFFSET( header, FIPS_BUF_GET_READER_SGE_LIST( header, current_segment->readers_offset, j))) ->lock));

      (((fips_buf_list_t *)APPLY_POINTER_OFFSET(
            header, FIPS_BUF_GET_READER_SGE_LIST(
                        header, current_segment->readers_offset, j)))
           ->capacity) = arg->max_sqe_count;
    }
    current_segment->index = i;
    current_segment->data_offset =
        (current_segment->readers_offset) +
        arg->max_reader_count *
            (sizeof(fips_buf_pointer_t) + // pointers of readers
             sizeof(fips_buf_list_t) +
             sizeof(fips_buf_sqe_t) *
                 arg->max_sqe_count); // sqe list of readers
    if (i < arg->max_segment_count - 1) {
      uintptr_t next_segment_offset =
          FIPS_BUF_GET_SEGMENT_HEADER(header, (i + 1));
      fips_buf_segment_header_t *next_segment =
          APPLY_POINTER_OFFSET(header, next_segment_offset);
      current_segment->next_offset = next_segment_offset;
      next_segment->prev_offset = GET_POINTER_OFFSET(header, current_segment);
      current_segment = next_segment;
    } else {
      current_segment->next_offset = 0;
    }
  }
  header->initialized = 1;
  return 0;
}

int read_config_file(const char *config_file, fips_buf_arg_t *arg) {
  
  config_t cfg;
  config_init(&cfg);
  int value;

  if (! config_read_file(&cfg, config_file)) {
    fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
    config_destroy(&cfg);
  }

  if (config_lookup_string(&cfg, "shm_name", &arg->shm_name) != CONFIG_TRUE) {
    fprintf(stderr, "shm_name must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  }

  //flags
  if (config_lookup_int(&cfg, "flags", &value) != CONFIG_TRUE) {
    fprintf(stderr, "flags must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  } else {
    arg->flags = value;
  }

  //line_count_exp
  if (config_lookup_int(&cfg, "line_count_exp", &value) != CONFIG_TRUE) {
    fprintf(stderr, "line_count_exp must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  }else{
    arg->line_count_exp = value;
  }

  //max_reader_count
  if (config_lookup_int(&cfg, "max_reader_count", &value) != CONFIG_TRUE) {
    fprintf(stderr, "max_reader_count must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  }else{
    arg->max_reader_count = value;
  }

  //max_reader_thread_count
  if(config_lookup_int(&cfg, "max_reader_thread_count", &value) != CONFIG_TRUE) {
    fprintf(stderr, "max_reader_thread_count must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE; 
  }else{
    arg->max_reader_thread_count = value;
  }
  
  //max_segment_count
  if (config_lookup_int(&cfg, "max_segment_count", &value) != CONFIG_TRUE) {
    fprintf(stderr, "max_segment_count must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  }else{
    arg->max_segment_count = value;
  }

  //line_size
  if (config_lookup_int(&cfg, "line_size", &value) != CONFIG_TRUE) {
    fprintf(stderr, "line_size must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  }else{
    arg->line_size = value;
  }

  //max_sqe_count
  if(config_lookup_int(&cfg, "max_sqe_count", &value) != CONFIG_TRUE) {
    fprintf(stderr, "max_sqe_count must be set\n");
    config_destroy(&cfg);
    return FIPS_BUF_ERROR_CONFIG_FILE;
  }
  else{
    arg->max_sqe_count = value;
  }

  return FIPS_BUF_SUCCESS;
}

int fips_buf_init(fips_buf_arg_t *arg, const char * config_file) {
  sem_t *init_sem;
  key_t key;
  int s;
  ssize_t segment_size;

  if (config_file != NULL) {
     if (access(config_file, F_OK | R_OK) == -1) {
      perror("cannot access config file");
      return FIPS_BUF_ERROR_CONFIG_FILE; 
    }
    if (read_config_file(config_file, arg) != FIPS_BUF_SUCCESS) {
      return FIPS_BUF_ERROR_CONFIG_FILE;
    }
  }

  //ensure file shm_name exists for ftok
  struct stat st;
    
    // Check if the file exists
  if (stat(arg->shm_name, &st) == -1) {
  int fd = creat(arg->shm_name, 0666);
  if (fd == -1 && errno != EEXIST) {
      perror("Failed to create handle for sysv shared memory");
      exit(EXIT_FAILURE);
  }
  close(fd); // Close the file descriptor
  }
  //
  // append _sem_open to the name of the shared memory
  if (strlen(arg->shm_name) > NAME_MAX - 4 - 10) {
    return FIPS_BUF_ERROR_INVALID_SHM_NAME;
  }
  // FIXME: check all other parameters
  char sem_name[NAME_MAX];
  char posix_sem_name[NAME_MAX] = "/";
  strcpy(sem_name, arg->shm_name);
  strcat(sem_name, "_sem_open");
  strcat(posix_sem_name, basename(sem_name));
  init_sem = sem_open(posix_sem_name, O_CREAT, FIPS_BUF_PERM, 1);
  if (init_sem == SEM_FAILED) {
    perror("sem_open");
    fprintf(stderr, "[FIPS_BUF] init: sem_open failed\n");
    return FIPS_BUF_ERROR_MUTEX;
  }
  while ((s = sem_wait(init_sem)) == -1 &&
         errno == EINTR) { // restart if interrupted by handler
    continue;
  }
  if (s == -1) {
    fprintf(stderr, "[FIPS_BUF] init: sem_wait failed\n");
    return FIPS_BUF_ERROR_MUTEX;
  }
  // we have exclusive access
  key = ftok(arg->shm_name, 1);
  if (key == -1) {
    perror("ftok");
    fprintf(stderr, "[FIPS_BUF] init: ftok failed\n");
    sem_post(init_sem);
    return FIPS_BUF_ERROR_INVALID_SHM_NAME;
  }
  segment_size = calculate_shared_memory_size(arg);
#ifdef DEBUG
  fprintf(stderr, "segment_size: %ld\n", segment_size);
  fflush(stderr);
#endif
  if (segment_size == -1) {
    fprintf(stderr, "[FIPS_BUF] init: calculate_segment_size failed\n");
    sem_post(init_sem);
    return FIPS_BUF_ERROR_INVALID_SHM_SIZE;
  }
  arg->shm_id =
      shmget(key, segment_size, IPC_CREAT | FIPS_BUF_PERM | SHM_HUGETLB |SHM_HUGE_1GB);
  if (arg->shm_id == -1) {
    fprintf(stderr, "[FIPS_BUF] init: could't get 1G hugepage trying normal pages\n");
    arg->shm_id = shmget(key, segment_size, IPC_CREAT | FIPS_BUF_PERM);
    if (arg->shm_id == -1) {
      fprintf(stderr, "[FIPS_BUF] init: shmget failed\n");
      sem_post(init_sem);
      return FIPS_BUF_ERROR_SHM;
    }
  }

  arg->header = shmat(arg->shm_id, NULL, 0);
  if (arg->header == (void *)-1) {
    fprintf(stderr, "[FIPS_BUF] init: shmat failed\n");
    sem_post(init_sem);
    return FIPS_BUF_ERROR_SHM;
  }

  if (setup_shm(arg) != 0) {
    fprintf(stderr, "[FIPS_BUF] init: setup_shm failed\n");
    sem_post(init_sem);
    return FIPS_BUF_ERROR_SHM;
  }

  if (checksum(arg) != 0) {
    fprintf(stderr, "[FIPS_BUF] init: checksum failed\n");
    sem_post(init_sem);
    return FIPS_BUF_ERROR_CHECKSUM;
  }

  if (arg->role == FIPS_WRITER) {
    if (arg->header->writer_count > 0) {
      fprintf(stderr, "[FIPS_BUF] init: writer already attached \n");
      sem_post(init_sem);
      return FIPS_BUF_ERROR_WRITER_ALREADY_ATTACHED;
    }
    arg->header->writer_count++;
  }
  if (arg->role == FIPS_READER) {
    // FIXME: allow reader to disconnect and reconnect
    arg->reader_index = arg->header->reader_count;
    arg->header->reader_count++;
  }
  sem_post(init_sem);

  return FIPS_BUF_SUCCESS;
}

int get_reader_thread_count(fips_buf_assignment_t *reader_assignment,
                            fips_buf_header_t *header) {
  int i = 0;
  int count = 0;
  while (i < header->max_reader_thread_count) {
    if (reader_assignment[i].flags & FIPS_BUF_FLAG_IN_USE)
      count++;
    i++;
  }
  return count;
}

int get_writer_thread_count(fips_buf_header_t *header) {
  int i = 0;
  int count = 0;
  while (i < header->segment_count) {
    if (((uint8_t *)APPLY_POINTER_OFFSET(
            header, header->writer_assignments_offset))[i] == FIPS_BUF_FLAG_IN_USE) {
      count++;
    }
    i++;
  }
  return count;
}

int reassaign_readers(fips_buf_header_t *header) {
  int active_writer_threads = get_writer_thread_count(header);
  for (int i = 0; i < header->reader_count; i++) {
    fips_buf_assignment_t *reader_assignment = APPLY_POINTER_OFFSET(
        header, FIPS_BUF_GET_READER_ASSIGNMENTS(header, i));
    int active_reader_threads =
        get_reader_thread_count(reader_assignment, header);
    if (active_reader_threads < 1) {
      continue;
    }
    if (active_writer_threads <
        1) { // no writer, if the last writer just detached, we need to make
             // sure that all readers disconnect
      for (int j = 0; j < header->max_reader_thread_count; j++) {
        if (reader_assignment[j].flags & FIPS_BUF_FLAG_IN_USE) {
          reader_assignment[j].start_segment = 0;
          reader_assignment[j].count = 0;
        }
      }
    } else { // we have a writer
      uint8_t active_writers[active_writer_threads];
      int acitve_writer_index = 0;
      uint8_t *writer_assignments = (uint8_t *)APPLY_POINTER_OFFSET(
          header, header->writer_assignments_offset);
      for (int j = 0; j < header->segment_count; j++) {
        if (writer_assignments[j] != 0) {
          active_writers[acitve_writer_index] = j;
          acitve_writer_index++;
        }
      }
      int writer_per_reader = active_writer_threads / active_reader_threads;
      if (writer_per_reader < 1) { // we have more reader threads
        int reader_per_writer = active_reader_threads / active_writer_threads;
        int remainder = active_reader_threads % active_writer_threads;
        int assigned_readers = 0;
        for (int j = 0; j < header->max_reader_thread_count; j++) {
          if (reader_assignment[j].flags & FIPS_BUF_FLAG_IN_USE) {
            if (assigned_readers < active_writer_threads * reader_per_writer) {
              reader_assignment[j].start_segment =
                  active_writers[assigned_readers / reader_per_writer];
              reader_assignment[j].count = 1;
              assigned_readers++;
            } else {
              remainder--;
              reader_assignment[j].start_segment = active_writers[remainder];
              reader_assignment[j].count = 1;
              assigned_readers++;
            }
          }
        }
      } else { // we have more writers or equal
        int assigned_writers = 0;
        int remainder = active_writer_threads % active_reader_threads;
        for (int j = 0; j < header->max_reader_thread_count; j++) {
          if (reader_assignment[j].flags & FIPS_BUF_FLAG_IN_USE) {
            if (remainder > 0) {
              reader_assignment[j].start_segment =
                  active_writers[assigned_writers];
              reader_assignment[j].count = writer_per_reader + 1;
              assigned_writers += writer_per_reader + 1;
              remainder--;
            } else {
              reader_assignment[j].start_segment =
                  active_writers[assigned_writers];
              reader_assignment[j].count = writer_per_reader;
              assigned_writers += writer_per_reader;
            }
          }
        }
      }
    }
  }
  return 0;
}

int fips_buf_attach(fips_buf_thread_arg_t *arg) {
  if (arg->process_arg == NULL || arg->process_arg->header->initialized == 0) {
    return FIPS_BUF_ERROR_UNINITIALIZED;
  }
  fips_buf_header_t *header = arg->process_arg->header;

  if (pthread_mutex_lock(&header->assignment_lock) == -1) {
    fprintf(stderr, "[FIPS_BUF] init: mutex_lock failed\n");
    return FIPS_BUF_ERROR_MUTEX;
  }

  uint8_t *writer_assignments = (uint8_t *)APPLY_POINTER_OFFSET(
      header, header->writer_assignments_offset);
  if (arg->process_arg->role == FIPS_WRITER) {
    int i = 0;
    while (i < header->segment_count && writer_assignments[i] != FIPS_BUF_FLAG_FREE) {
      i++;
    }
    if (writer_assignments[i] == FIPS_BUF_FLAG_FREE) { // found free segment
      writer_assignments[i] = FIPS_BUF_FLAG_IN_USE;
      arg->thread_index = i;
#ifdef DEBUG
      printf("thread_index: %d\n", arg->thread_index);
      fflush(stdout);
#endif
      // #pragma clang diagnostic push
      // #pragma gcc diagnostic push
      // #pragma clang diagnostic ignored "-Wincompatible-pointer-types"
      // #pragma gcc diagnostic ignored "-Wincompatible-pointer-types"
      arg->current_segment = (fips_buf_segment_header_t **)APPLY_POINTER_OFFSET(
          header, header->first_segment_offset);
      for (int j = 0; j < i; j++) {
        arg->current_segment =
            ((fips_buf_segment_header_t **)APPLY_POINTER_OFFSET(
                header, (((fips_buf_segment_header_t *)arg->current_segment)
                             ->next_offset)));
      }
      arg->assigned_index = ((fips_buf_pointer_t **)&(
          ((fips_buf_segment_header_t *)arg->current_segment)->writer));
      // #pragma clang diagnostic pop
      // #pragma gcc diagnostic pop
    } else {
      pthread_mutex_unlock(&header->assignment_lock);
      return FIPS_BUF_ERROR_NO_FREE_SEGMENT;
    }
  }
  if (arg->process_arg->role == FIPS_READER) {
    fips_buf_assignment_t *reader_assignment = APPLY_POINTER_OFFSET(
        header, FIPS_BUF_GET_READER_ASSIGNMENTS(
                    header, arg->process_arg->reader_index));
    int i = 0;
    while (i < header->max_reader_thread_count &&
           reader_assignment[i].flags & FIPS_BUF_FLAG_IN_USE) {
      i++;
    }
    if (reader_assignment[i].tag == 0) { // found a free reader slot
      reader_assignment[i].flags = FIPS_BUF_FLAG_IN_USE;
      arg->thread_index = i;
#ifdef DEBUG
      printf("thread_index: %d\n", arg->thread_index);
      fflush(stdout);
#endif
      arg->assignment = &reader_assignment[i];
      arg->current_segment =
          calloc(header->segment_count, sizeof(fips_buf_segment_header_t *));
      arg->assigned_index =
          calloc(header->segment_count, sizeof(fips_buf_pointer_t *));
    } else {
      pthread_mutex_unlock(&header->assignment_lock);
      return FIPS_BUF_ERROR_NO_FREE_SEGMENT;
    }
  }
  reassaign_readers(header);
  header->assignment_generation++;
  pthread_mutex_unlock(&header->assignment_lock);
  return 0;
}

// returns the number of readers to which the flag was added
int add_flag_affected_readers(fips_buf_header_t *header, uint8_t thread_index,
                              uint16_t flags) {

  int affected_readers = 0;
  for (int i = 0; i < header->reader_count; i++) {
    fips_buf_assignment_t *reader_assignment = APPLY_POINTER_OFFSET(
        header, FIPS_BUF_GET_READER_ASSIGNMENTS(header, i));
    uint8_t *writer_assignments = (uint8_t *)APPLY_POINTER_OFFSET(
        header, header->writer_assignments_offset);
    for (int j = 0; j < header->max_reader_thread_count; j++) {
      if (reader_assignment[j].flags & FIPS_BUF_FLAG_IN_USE) {
        int c = 0;
        for (int k = 0; c < reader_assignment[j].count; k++) {
          if (reader_assignment[j].start_segment + k >= header->segment_count) {
#ifdef DEBUG
            fflush(stdout);
            fprintf(stderr, "[FIPS_BUF] Assignment structure corrupted!!!\n");
#endif
            return FIPS_BUF_ERROR_CORRUPTED;
          }
          if (writer_assignments[reader_assignment[j].start_segment + k] == 1) {
            if (reader_assignment[j].start_segment + k == thread_index) {
              reader_assignment[j].flags |= flags;
              affected_readers ++;
            }
            c++;
          }
        }
      }
    }
  }
  return affected_readers;
}

int fips_buf_detach(fips_buf_thread_arg_t *arg) {
  if (arg->process_arg == NULL || arg->process_arg->header->initialized == 0) {
    return FIPS_BUF_ERROR_UNINITIALIZED;
  }
  fips_buf_header_t *header = arg->process_arg->header;
  uint8_t *writer_assignments = (uint8_t *)APPLY_POINTER_OFFSET(
      header, header->writer_assignments_offset);

  if (pthread_mutex_lock(&header->assignment_lock) == -1) {
    fprintf(stderr, "[FIPS_BUF] init: mutex_lock failed\n");
    return FIPS_BUF_ERROR_MUTEX;
  }
  if (arg->process_arg->role == FIPS_WRITER) {
    int reader_count = add_flag_affected_readers(header, arg->thread_index,
                              FIPS_BUF_FLAG_TRAILING);
    if (reader_count > 0) {
      writer_assignments[arg->thread_index] = FIPS_BUF_FLAG_TRAILING;
    } else{
      writer_assignments[arg->thread_index] = FIPS_BUF_FLAG_FREE;
    }

    arg->current_segment = NULL;
    arg->assigned_index = NULL;
  }
  if (arg->process_arg->role == FIPS_READER) {
    arg->assignment->tag = 0;
    if (arg->current_segment != NULL) {
      free(arg->current_segment);
    }
    if (arg->assigned_index != NULL) {
      free(arg->assigned_index);
    }
  }
  reassaign_readers(header);
  header->assignment_generation++;
  pthread_mutex_unlock(&header->assignment_lock);

  return 0;
}

int fips_buf_destroy(fips_buf_arg_t *arg, uint8_t flags) {
  // FIXME: allow readers to disconnect and reconnect
  // FIXME: should be protected by the sem_open semaphore
  if (arg->header->initialized == 0) {
    return FIPS_BUF_ERROR_UNINITIALIZED;
  }
  uint8_t *writer_assignments = (uint8_t *)APPLY_POINTER_OFFSET(
      arg->header, arg->header->writer_assignments_offset);
  if (arg->role == FIPS_WRITER) {
    if (get_writer_thread_count(arg->header) > 1 &&
        !(flags & FIPS_BUF_FLAG_FORCE)) {
      fprintf(stderr, "[FIPS_BUF] destroy: writer threads still attached\n");
      return FIPS_BUF_ERROR_THREADS_STILL_ATTACHED;
    }
    // FIXME: this destroys all information for trailing readers
    //memset(writer_assignments, 0, arg->max_segment_count * sizeof(uint8_t));
    arg->header->writer_count -= 1;
  }
  if (arg->role == FIPS_READER) {
    fips_buf_assignment_t *reader_assignment = APPLY_POINTER_OFFSET(
        arg->header,
        FIPS_BUF_GET_READER_ASSIGNMENTS(arg->header, arg->reader_index));
    if (get_reader_thread_count(reader_assignment, arg->header) > 1 &&
        !(flags & FIPS_BUF_FLAG_FORCE)) {
      fprintf(stderr, "[FIPS_BUF] destroy: reader threads still attached\n");
      return FIPS_BUF_ERROR_THREADS_STILL_ATTACHED;
    }
    memset(reader_assignment, 0,
           arg->max_reader_thread_count * sizeof(fips_buf_assignment_t));
    arg->header->reader_count -= 1;
  }
  pthread_mutex_lock(&arg->header->assignment_lock);
  reassaign_readers(arg->header);
  pthread_mutex_unlock(&arg->header->assignment_lock);

  if (flags & FIPS_BUF_FLAG_RM_FORCE ||
      (arg->header->writer_count == 0 && arg->header->reader_count == 0)) {
    arg->header->initialized = 2;
    shmdt(arg->header);
    shmctl(arg->shm_id, IPC_RMID, NULL);
  } else {
    shmdt(arg->header);
  }
  return 0;
}

void assert_segment_headers(fips_buf_thread_arg_t* arg){

  for (int i = 0; i < arg->assigned_reader_count; i++) {
    for (int j = 0; j < arg->process_arg->max_segment_count; j++) {
      if (arg->current_segment[i] == (fips_buf_segment_header_t *) FIPS_BUF_GET_SEGMENT_HEADER(arg->process_arg->header, j)) {
        break;
      }
      if (arg->current_segment[i] < (fips_buf_segment_header_t *) FIPS_BUF_GET_SEGMENT_HEADER(arg->process_arg->header, j)) {
        assert(0); 
      }
    }
  }
}

int update_cached_reader_values(fips_buf_thread_arg_t *arg) {
  // FIXME: is this correct?
  // FIXME: handle FIPS_BUF_FLAG_TRAILING
  if (arg->assignment == NULL) {
    return -1;
  }
  pthread_mutex_lock(&arg->process_arg->header->assignment_lock);
  fips_buf_assignment_t *reader_assignment = arg->assignment;
  uint8_t *writer_assignments =
      APPLY_POINTER_OFFSET(arg->process_arg->header,
                           arg->process_arg->header->writer_assignments_offset);
  int correct_writer_index = 0;
  

  int cached_count = arg->assigned_reader_count + arg->trailing_buffers_count;
  fips_buf_segment_header_t* tmp_segments[cached_count];
  fips_buf_pointer_t* tmp_pointers[cached_count];
  int tmp_count = 0;
  for (int i = 0; i < cached_count; i++) {
    if( writer_assignments[arg->current_segment[i]->index] == FIPS_BUF_FLAG_TRAILING){
      tmp_segments[tmp_count] = arg->current_segment[i];
      tmp_pointers[tmp_count] = arg->assigned_index[i];
      tmp_count++;
    }
  }
  arg->assigned_reader_count = reader_assignment->count;
  memset(arg->current_segment, 0,
         arg->process_arg->header->segment_count *
             sizeof(fips_buf_segment_header_t *));
  memset(arg->assigned_index, 0,
         arg->process_arg->header->segment_count *
             sizeof(fips_buf_pointer_t *));
  for (int c = 0; c < reader_assignment->count; c++) {
    while (writer_assignments[reader_assignment->start_segment +
                              correct_writer_index] != FIPS_BUF_FLAG_IN_USE) {
      correct_writer_index++;
      if (reader_assignment->start_segment + correct_writer_index >=
          arg->process_arg->header->segment_count) {
        fprintf(stderr, "[FIPS_BUF] Assignment structure corrupted!!!\n");
        pthread_mutex_unlock(&arg->process_arg->header->assignment_lock);
        return FIPS_BUF_ERROR_CORRUPTED;
      }
    }
    arg->current_segment[c] =
        APPLY_POINTER_OFFSET(arg->process_arg->header,
                             arg->process_arg->header->first_segment_offset);
    for (uint32_t i = 0;
         i < reader_assignment->start_segment + correct_writer_index; i++) {
      arg->current_segment[c] = APPLY_POINTER_OFFSET(
          arg->process_arg->header, arg->current_segment[c]->next_offset);
    }
    arg->assigned_index[c] = APPLY_POINTER_OFFSET(
        arg->process_arg->header,
        FIPS_BUF_GET_READER(arg->process_arg->header,
                            arg->current_segment[c]->readers_offset,
                            arg->process_arg->reader_index));
    correct_writer_index++;
  }
  for (int i = 0; i < tmp_count; i++) {
    arg->current_segment[arg->assigned_reader_count + i] = tmp_segments[i];
    arg->assigned_index[arg->assigned_reader_count + i] = tmp_pointers[i];
  }
  arg->trailing_buffers_count = tmp_count;
  arg->assignment_generation = arg->process_arg->header->assignment_generation;
  assert_segment_headers(arg);

  pthread_mutex_unlock(&arg->process_arg->header->assignment_lock);
  return 0;
}

void remove_cached_entries(fips_buf_thread_arg_t *arg, uint8_t rotation) {
  if(rotation >= arg->assigned_reader_count){
    memmove(arg->current_segment + rotation, arg->current_segment + rotation + 1,
            (arg->assigned_reader_count + arg->trailing_buffers_count - rotation - 1) *
                sizeof(fips_buf_segment_header_t *));
    memmove(arg->assigned_index + rotation, arg->assigned_index + rotation + 1,
            (arg->assigned_reader_count + arg->trailing_buffers_count - rotation - 1) *
                sizeof(fips_buf_pointer_t *));
    arg->trailing_buffers_count--;
  }
}

// fills the provided iovecs with content from the ring buffer
int fips_buf_read(fips_buf_thread_arg_t *arg, struct iovec *iov, int iovcnt,
                  uint64_t *tag, int8_t flags) {

  // FIXME: add workloadstealing
  if (unlikely(flags != 0)) {
    return FIPS_BUF_ERROR_NOT_IMPLEMENTED;
  }

  static __thread uint8_t rotation = 0;
  int ret = 0;
  if (unlikely(arg->assignment_generation !=
      arg->process_arg->header->assignment_generation)) {
    if ((ret = update_cached_reader_values(arg)) != 0) {
      return ret;
    }
  }
  // we try to read from all our segments starting indexed by rotation
  int tries = 0;
  int cached_count = arg->assigned_reader_count + arg->trailing_buffers_count;
try_again:
  while (tries < cached_count) {
    // determine on which segment the reader is currently reading
    rotation++;
    if (cached_count <= rotation) {
      rotation = 0;
    }
    tries++;

    // get the current segment info
    fips_buf_segment_header_t *current_segment = arg->current_segment[rotation];
    fips_buf_pointer_t *current_reader = arg->assigned_index[rotation];

    uint32_t current_head_offset;
    uint32_t new_head_offset;
    // try to atomically update
    do {
      current_head_offset = current_reader->head_offset;
      new_head_offset =
          (current_head_offset + iovcnt) & arg->process_arg->header->line_MASK;
#ifdef DEBUG
      printf("current_head_offset: %d, new_head_offset %d , current_segment: "
             "%d, current_segment->writer.commit_offset %d, "
             "current_segment->writer.head_offset %d,  current_reader %p, "
             "rotation: %d, assigned_reader_count %d \n",
             current_head_offset, new_head_offset, current_segment->index,
             current_segment->writer.commit_offset,
             current_segment->writer.head_offset, current_reader, rotation,
             arg->assigned_reader_count);
      fflush(stdout);
#endif
      if (new_head_offset > current_head_offset && // no wrap around
          current_segment->writer.commit_offset >= current_head_offset &&
          current_segment->writer.commit_offset < new_head_offset) {
          remove_cached_entries(arg, rotation);
        // FIXME: remove trailing entries
        goto try_again;
      }
      if (new_head_offset < current_head_offset && // wrap around
          (current_segment->writer.commit_offset >= current_head_offset ||
           current_segment->writer.commit_offset < new_head_offset)) {
          remove_cached_entries(arg, rotation);
        // FIXME: remove trailing entries
        goto try_again;
      }
    } while (atomic_compare_exchange_weak(&current_reader->head_offset,
                                          &current_head_offset,
                                          new_head_offset) == false);

    // fill the iovecs
    for (int i = 0; i < iovcnt; i++) {
      iov[i].iov_base = APPLY_POINTER_OFFSET(
          arg->process_arg->header,
          current_segment->data_offset +
              ((arg->process_arg->line_size + LINE_WIDTH_SIZE) *
               ((current_head_offset + i) &
                arg->process_arg->header->line_MASK)) +
              LINE_WIDTH_SIZE);
      iov[i].iov_len = *(((uint16_t *)iov[i].iov_base) - 1);
    }
    ((fips_buf_range_t *)tag)->start_index = current_head_offset;
    ((fips_buf_range_t *)tag)->count = iovcnt;
    ((fips_buf_range_t *)tag)->reader_index = arg->process_arg->reader_index;
    ((fips_buf_range_t *)tag)->segment_index = current_segment->index;

    return 0;
  }
  return FIPS_BUF_ERROR_EMPTY;
}

int fips_buf_list_add_sqe(fips_buf_pointer_t *reader, fips_buf_range_t tag,
                          uint32_t mask) {

  bool locked = false;
  int need_to_lock = 0;
  fips_buf_list_t *list = (fips_buf_list_t *)(reader + 1);
#ifdef DEBUG
  fprintf(
      stderr,
      "list->write_index: %lu, list->read_index: %lu list->first_offset: %d \n",
      list->write_index, list->read_index, list->first_offset);
  fflush(stderr);
#endif
  // are we in order?
  if (reader->commit_offset == tag.start_index) {
    reader->commit_offset = (reader->commit_offset + tag.count) & mask;
    need_to_lock = 1;
  } else {
    // add to sqe list
    pthread_mutex_lock(&list->lock);
    locked = true;
    size_t new_write_index = (list->write_index + 1) % list->capacity;
    if (list->read_index == new_write_index) { // look here ! //FIXME: this do we have enough space?
      fprintf(stderr, "[FIPS_BUF] sqe list full\n");
      pthread_mutex_unlock(&list->lock);
      return FIPS_BUF_ERROR_NO_SPACE;
    }
    size_t index = list->write_index;
    list->write_index = new_write_index;
    fips_buf_sqe_t *data = (fips_buf_sqe_t *)(list + 1);
    data[index].range.tag = tag.tag;
    data[index].next_offset = 0;

    uintptr_t new_sqe_offset = GET_POINTER_OFFSET(list, &data[index]);
    uintptr_t current_sqe_offset = list->first_offset;
    if (current_sqe_offset == 0) {
      list->first_offset = new_sqe_offset;
#ifdef DEBUG
      fprintf(stderr,
              "inserted first reader_commit_offset %d, tag.start_index %d, "
              "tag.count %d, rtag.reader_index %d, rtag.segment_index %d \n",
              reader->commit_offset, tag.start_index, tag.count,
              tag.reader_index, tag.segment_index);
      fflush(stderr);
#endif
    } else {
      fips_buf_sqe_t *prev_sqe = NULL;
      do {
        fips_buf_sqe_t *current_sqe =
            APPLY_POINTER_OFFSET(list, current_sqe_offset);
#ifdef DEBUG
        fprintf(stderr,
                "current_sqe %d reader_commit_offset %d, tag.start_index %d, "
                "tag.count %d, rtag.reader_index %d, rtag.segment_index %d "
                "current_sqe_offset: %d, current_sqe_next_offset %d \n",
                current_sqe->range.start_index, reader->commit_offset,
                tag.start_index, tag.count, tag.reader_index, tag.segment_index,
                current_sqe_offset, current_sqe->next_offset);
        fflush(stderr);
#endif
        // if the element we want to add is bigger than the current we add before the current position
        if (current_sqe->range.start_index > tag.start_index ) {
          /* && tag.start_index >= reader->commit_offset)  // doesn't look right */
          if (prev_sqe != NULL) {
            prev_sqe->next_offset = new_sqe_offset;
          } else {
            list->first_offset = new_sqe_offset;
          }
          data[index].next_offset = current_sqe_offset;
          break;
        }
        // if the element we are on the end of the list we add it anyway
        if (current_sqe->next_offset == 0) {
          current_sqe->next_offset = new_sqe_offset;
          if (prev_sqe != NULL) {
            prev_sqe->next_offset = new_sqe_offset;
          } else {
            list->first_offset = new_sqe_offset;
          }
          break;
        }
#ifdef DEBUG
        if (current_sqe_offset == current_sqe->next_offset) {
          fprintf(stderr, "[FIPS_BUF] sqe list corrupted\n");
          fflush(stderr);
        }
#endif
        prev_sqe = current_sqe;
        current_sqe_offset = current_sqe->next_offset;
      } while (current_sqe_offset != 0);
    }
  }
  // cleanup list
  if (list->first_offset != 0) {
    if (need_to_lock) {
      pthread_mutex_lock(&list->lock);
      locked = true;
    }
    if (list->first_offset != 0 &&
        ((fips_buf_sqe_t *)APPLY_POINTER_OFFSET(list, list->first_offset))
                ->range.start_index == reader->commit_offset) {
      uintptr_t current_sqe_offset = list->first_offset;
      while (current_sqe_offset != 0 &&
             ((fips_buf_sqe_t *)APPLY_POINTER_OFFSET(list, current_sqe_offset))
                     ->range.start_index == reader->commit_offset) {
        fips_buf_sqe_t *current_sqe =
            APPLY_POINTER_OFFSET(list, current_sqe_offset);
        reader->commit_offset =
            (reader->commit_offset + current_sqe->range.count) & mask;
        list->first_offset = current_sqe->next_offset;
        current_sqe->range.tag = 0;
        current_sqe->next_offset = 0;
        current_sqe_offset = list->first_offset;
        
        list->read_index+=sizeof(fips_buf_sqe_t);
      }
    }
  }

  if (locked){
  pthread_mutex_unlock(&list->lock);}
  return FIPS_BUF_SUCCESS;
}

// returns the buffers pointed to by the tag to the ring buffer
int fips_buf_return(fips_buf_thread_arg_t *arg, uint64_t tag) {
  fips_buf_range_t rtag;
  rtag.tag = tag;
#ifdef DEBUG
  printf("called return: rtag.index %d, rtag.count %d, rtag.reader_index %d, "
         "rtag.segment_index %d \n",
         rtag.start_index, rtag.count, rtag.reader_index, rtag.segment_index);
  fflush(stdout);
#endif
  fips_buf_segment_header_t *current_segment =
      APPLY_POINTER_OFFSET(arg->process_arg->header,
                           FIPS_BUF_GET_SEGMENT_HEADER(arg->process_arg->header,
                                                       rtag.segment_index));
  fips_buf_pointer_t *reader = APPLY_POINTER_OFFSET(
      arg->process_arg->header,
      FIPS_BUF_GET_READER(arg->process_arg->header,
                          current_segment->readers_offset, rtag.reader_index));
  return fips_buf_list_add_sqe(reader, rtag,
                               arg->process_arg->header->line_MASK);
}

// fills the provided iovecs with buffers to write to
int fips_get_write_buffer(fips_buf_thread_arg_t *arg, struct iovec *iov,
                          int iovcnt) {

  fips_buf_segment_header_t *current_segment =
      (fips_buf_segment_header_t *)arg->current_segment;
  uint32_t current_head_offset = current_segment->writer.head_offset;

  uint32_t new_head_offset =
      (current_head_offset + iovcnt) & arg->process_arg->header->line_MASK;
  if (!(arg->process_arg->header->flags & FIPS_BUF_FLAG_OVERWRITE)) {
    // FIXME: reader processes can be randomly distributed over the segments
    for (int i = 0; i < arg->process_arg->header->reader_count; i++) {
      fips_buf_pointer_t *reader = APPLY_POINTER_OFFSET(
          arg->process_arg->header,
          FIPS_BUF_GET_READER(arg->process_arg->header,
                              current_segment->readers_offset, i));
      if (new_head_offset > current_head_offset && // no wrap around
          reader->commit_offset > current_head_offset &&
          reader->commit_offset <= new_head_offset) {
        return FIPS_BUF_ERROR_NO_SPACE;
      }
      if (new_head_offset < current_head_offset && // wrap around
          (reader->commit_offset > current_head_offset ||
           reader->commit_offset <= new_head_offset)) {
        return FIPS_BUF_ERROR_NO_SPACE;
      }
    }
  }
  current_segment->writer.head_offset = new_head_offset;

  // fill the iovecs
  for (int i = 0; i < iovcnt; i++) {
    iov[i].iov_base = APPLY_POINTER_OFFSET(
        arg->process_arg->header,
        current_segment->data_offset +
            ((arg->process_arg->line_size + LINE_WIDTH_SIZE) *
             ((current_head_offset + i) &
              arg->process_arg->header->line_MASK)) +
            LINE_WIDTH_SIZE);
    iov[i].iov_len = arg->process_arg->line_size;
  }
  return 0;
}

int fips_buf_write(fips_buf_thread_arg_t *arg, struct iovec *iov, int iovcnt) {

  // prepend iovlen to iov base
  // independent of ringbuf structure
  //
  for (int i = 0; i < iovcnt; i++) {
    uint16_t *iovlen = ((uint16_t *)iov[i].iov_base) - 1;
    *iovlen = iov[i].iov_len;
  }
  fips_buf_segment_header_t *current_segment =
      (fips_buf_segment_header_t *)arg->current_segment;
  uint32_t current_head_offset = current_segment->writer.head_offset;
  uint32_t current_commit_offset = current_segment->writer.commit_offset;

  uint32_t new_commit_offset =
      (current_commit_offset + iovcnt) & arg->process_arg->header->line_MASK;
  if (new_commit_offset > current_head_offset) {
    fprintf(stderr,
            "[FIPS_BUF] write: ringbuffers corrupted commit_offset %d write "
            "head: %d\n",
            new_commit_offset, current_head_offset);
    return FIPS_BUF_ERROR_CORRUPTED;
  }
  current_segment->writer.commit_offset = new_commit_offset;
  return 0;
}
