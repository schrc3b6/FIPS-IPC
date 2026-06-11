#include <shm_ringbuf.h>
#include <fips_buf.h>

void openlog(const char *tag, int options, int facility);

void syslog(int pri, const char *fmt, ...);