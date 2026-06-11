#include <stdatomic.h>
#include <stddef.h>
#include <sys/uio.h>
#include <stdint.h>
#include <pthread.h>
//#include <linux/shm.h>

#ifndef SHM_HUGE_SHIFT
#define SHM_HUGE_SHIFT	26
#define SHM_HUGE_MASK	0x3f

#define SHM_HUGE_16KB	(14 << SHM_HUGE_SHIFT)
#define SHM_HUGE_64KB	(16 << SHM_HUGE_SHIFT)
#define SHM_HUGE_512KB	(19 << SHM_HUGE_SHIFT)
#define SHM_HUGE_1MB	(20 << SHM_HUGE_SHIFT)
#define SHM_HUGE_2MB	(21 << SHM_HUGE_SHIFT)
#define SHM_HUGE_8MB	(23 << SHM_HUGE_SHIFT)
#define SHM_HUGE_16MB	(24 << SHM_HUGE_SHIFT)
#define SHM_HUGE_32MB	(25 << SHM_HUGE_SHIFT)
#define SHM_HUGE_256MB	(28 << SHM_HUGE_SHIFT)
#define SHM_HUGE_512MB	(29 << SHM_HUGE_SHIFT)
#define SHM_HUGE_1GB	(30 << SHM_HUGE_SHIFT)
#define SHM_HUGE_2GB	(31 << SHM_HUGE_SHIFT)
#define SHM_HUGE_16GB	(34U << SHM_HUGE_SHIFT)
#endif


#define likely(x)      __builtin_expect(!!(x), 1)
#define unlikely(x)    __builtin_expect(!!(x), 0)

#define LINE_WIDTH_SIZE 2
// Error codes
#define FIPS_BUF_SUCCESS 0
#define FIPS_BUF_ERROR_INVALID_SHM_NAME 1
#define FIPS_BUF_ERROR_INVALID_SHM_SIZE 2
#define FIPS_BUF_ERROR_INVALID_SHM_SEGMENT_SIZE 3
#define FIPS_BUF_ERROR_INVALID_SHM_SEGMENT_COUNT 4
#define FIPS_BUF_ERROR_INVALID_LINE_SIZE 5

#define FIPS_BUF_ERROR_MUTEX 6
#define FIPS_BUF_ERROR_SHM 7
#define FIPS_BUF_ERROR_WRITER_ALREADY_ATTACHED 8
#define FIPS_BUF_ERROR_CHECKSUM 9
#define FIPS_BUF_ERROR_UNINITIALIZED 10
#define FIPS_BUF_ERROR_NO_FREE_SEGMENT 11
#define FIPS_BUF_ERROR_THREADS_STILL_ATTACHED 12
#define FIPS_BUF_ERROR_NO_SPACE 13
#define FIPS_BUF_ERROR_CORRUPTED 14
#define FIPS_BUF_ERROR_EMPTY 15
#define FIPS_BUF_ERROR_NOT_IMPLEMENTED 16
#define FIPS_BUF_ERROR_CONFIG_FILE 17

#define FIPS_BUF_PERM 0644 // File permission on the shared memory segment

// FLAGs for destroy
#define FIPS_BUF_FLAG_FORCE 1
#define FIPS_BUF_FLAG_RM_FORCE 2

// FLAGs for read
#define FIPS_BUF_STEAL 1

//FLAGs arg/init
#define FIPS_BUF_FLAG_OVERWRITE 1
// #define FIPS_BUF_FLAG_OVERWRITE_PUSH 2 not implemented because incompatible with zero copy

//internal flags
#define FIPS_BUF_FLAG_FREE 0
#define FIPS_BUF_FLAG_IN_USE 1
#define FIPS_BUF_FLAG_TRAILING 2


enum fips_buf_role {
  FIPS_WRITER,
  FIPS_READER
};

enum fips_buf_state {
  FIPS_UNINITIALIZED = 0,
  FIPS_INITIALIZED = 1,
  FIPS_DESTROYED = 2,
};


typedef union fips_buf_range {
  struct __attribute__((packed)) {
    uint32_t start_index;
    uint16_t count;
    uint8_t segment_index; 
    uint8_t reader_index; 
  };
  uint64_t tag;
} fips_buf_range_t;

typedef struct fips_buf_sqe {
  fips_buf_range_t range;
  uintptr_t next_offset;
} fips_buf_sqe_t;

typedef union fips_buf_assignment {
  struct __attribute__((packed)) {
    uint32_t start_segment; // the start segment of the range
    uint16_t count;
    uint16_t flags; 
  };
  uint64_t tag;
} fips_buf_assignment_t;

//FIXME: make lock free
typedef struct fips_buf_list {
  size_t capacity;
  size_t count;
  size_t max_element;
  size_t write_index;
  size_t read_index;
  pthread_mutex_t lock;
  uintptr_t first_offset;
  //fips_buf_range_t ranges;
} fips_buf_list_t;


typedef struct fips_buf_pointer {
  _Atomic uint32_t head_offset;
  _Atomic uint32_t commit_offset;
} fips_buf_pointer_t;


// Layout of the shared memory buffer
// because we want to make it flexible to add writers and readers at runtime we adopt the following layout
// 1.1. header
// 1.2. segment_assignment
// 2.1. segment_header
// 2.2. reader lists
// 2.3. segment_data
// 3.1. segment_header
// 3.2. reader lists
// 3.3. segment_data
// ...
// segment_assignment 
// list header + 
// (segment_count * sizeof(fips_buf_range_t) +  //writer
// max_reader_count * max_reader_thread_count * sizeof(fips_buf_pointer_t)) //readers
//
// reader lists
// list header * (max_reader_count *( sizeof(fips_buf_pointer_t) + sizeof(fips_buf_range_t)* max_sqe_count)) 
//

#define APPLY_POINTER_OFFSET(ptr, offset) ((void *)(((uintptr_t)ptr) + (offset)))
#define GET_POINTER_OFFSET(ptra, ptrb) ((uintptr_t)(ptrb) - (uintptr_t)(ptra)) 

#define FIPS_BUF_GET_SEGMENT_HEADER(header, segment_index) \
(header->first_segment_offset + (segment_index) * (sizeof(fips_buf_segment_header_t) + header->max_reader_count * (sizeof(fips_buf_pointer_t) + sizeof(fips_buf_list_t) + sizeof(fips_buf_sqe_t) * header->max_sqe_count) + (header->line_size+LINE_WIDTH_SIZE) * (1 << header->line_count_exp)))

#define FIPS_BUF_GET_READER(header, readers_offset, reader_index) \
(readers_offset + (reader_index) * (sizeof(fips_buf_pointer_t) + sizeof(fips_buf_list_t) + sizeof(fips_buf_sqe_t) * header->max_sqe_count ))

#define FIPS_BUF_GET_READER_SGE_LIST(header, readers_offset, reader_index) \
((readers_offset) + (reader_index) * (sizeof(fips_buf_pointer_t) + sizeof(fips_buf_list_t) + sizeof(fips_buf_sqe_t) * header->max_sqe_count ) + sizeof(fips_buf_pointer_t))

#define FIPS_BUF_GET_READER_ASSIGNMENTS(header, reader_index) \
((header->reader_assignments_offset) + (reader_index) * header->max_reader_thread_count * sizeof(fips_buf_assignment_t))

typedef struct fips_buf_segment_header {
  uintptr_t next_offset;
  uintptr_t prev_offset;
  uint8_t index;
  fips_buf_pointer_t writer;
  uintptr_t readers_offset;
  uintptr_t data_offset;
} fips_buf_segment_header_t;

typedef struct fips_buf_header {
  atomic_uchar initialized;
  _Atomic uint64_t assignment_generation;
  pthread_mutex_t assignment_lock;
  uint64_t checksum;
  uint8_t segment_count;
  uint8_t max_reader_count; //maximum number of readers process can attach
  uint8_t max_reader_thread_count; //maximum number of threads per reader
  uint8_t reader_count; //currently attached readers
  uint8_t writer_count; //currently attached writers, should always be <= 1
  uint8_t line_count_exp;
  uint8_t flags;
  uint32_t line_size;
  uint32_t max_sqe_count;
  uint64_t line_MASK;
  uintptr_t first_segment_offset;
  uintptr_t last_segment_offset;
  uintptr_t writer_assignments_offset;
  uintptr_t reader_assignments_offset;
} fips_buf_header_t;


typedef struct fips_buf_arg {
  // The following fields need to be set by the user
  // the requested role
  enum fips_buf_role role;
  // the human readable name of the shared memory
  const char *shm_name;
  // flags
  uint8_t flags;
  // the number of line elements as a power of 2; a line however can be broken over multiple line elements
  uint8_t line_count_exp;
  // the maximum number of different readers
  uint8_t max_reader_count;
  // the maximum number of threads per reader
  uint8_t max_reader_thread_count;
  // the maximum number of writers threads -> one writer thread per segment
  uint8_t max_segment_count;
  // the size of a line element
  uint32_t line_size;
  // the numher of sqe that can be requested per segment per reader  
  uint32_t max_sqe_count;

  // the following fields are set during process initialization
  int shm_id;
  fips_buf_header_t *header;
  // the x reader process is ignored as writer
  uint8_t reader_index;
} fips_buf_arg_t;


typedef struct fips_buf_trailing_buf_element {
  struct fips_buf_trailing_buf_element *next;
  struct fips_buf_trailing_buf_element *prev;
  fips_buf_segment_header_t *segment;
  fips_buf_pointer_t *index;
} fips_buf_trailing_buf_element_t;

typedef struct fips_buf_trailing_buf_list {
  struct fips_buf_trailing_buf_element *head;
  int count;
} fips_buf_trailing_buf_t;

typedef struct fips_buf_thread_arg {
  fips_buf_arg_t *process_arg;
  //NOTE: this should never wrap around
  uint64_t assignment_generation;
  uint8_t thread_index;
  //optimization to not recalulate all addresses
  fips_buf_segment_header_t **current_segment; // points to array in process memory for writers
  fips_buf_pointer_t **assigned_index; // points to array in process memory for readers
  fips_buf_assignment_t* assignment; // reader only set during attachements

  uint8_t assigned_reader_count;
  uint8_t trailing_buffers_count;
} fips_buf_thread_arg_t;

typedef struct fips_bin_message {
  time_t timestamp;
  uint8_t address_len;
  union {
    uint32_t address4;
    uint8_t address_arr4[4];
    uint8_t address_arr6[16];
    #ifdef __SIZEOF_INT128__
    unsigned __int128 address6;
    #endif
  };
  unsigned int data_len;
  char data;
} fips_bin_message_t;


// needs to be called once per process
int fips_buf_init(fips_buf_arg_t *arg, const char * config_file);

// needs to be called once by each thread that wants to use the buffer
int fips_buf_attach(fips_buf_thread_arg_t *arg);

// needs to be called by each thread 
int fips_buf_detach(fips_buf_thread_arg_t *arg);

// needs to be called on cleanup once per process
int fips_buf_destroy(fips_buf_arg_t *arg, uint8_t flags);

// fills the provided iovecs with content from the ring buffer
int fips_buf_read(fips_buf_thread_arg_t *arg, struct iovec *iov, int iovcnt,
                  uint64_t *tag, int8_t flags);

// returns the buffers pointed to by the tag to the ring buffer
int fips_buf_return(fips_buf_thread_arg_t *arg, uint64_t tag);

// fills the provided iovecs with buffers to write to 
int fips_get_write_buffer(fips_buf_thread_arg_t *arg, struct iovec *iov, int iovcnt);

// commits the buffers provided by fips_get_write_buffer
int fips_buf_write(fips_buf_thread_arg_t *arg, struct iovec *iov, int iovcnt);
