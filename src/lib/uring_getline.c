#include "include/uring_getline.h"

static inline int _rdline(u_int32_t * offset, uint32_t * rsize, char * buf, char ** lineptr)
{
    uint32_t lsize, start = *offset;

    while(*offset < *rsize)
    {
        if(buf[(*offset)++] == '\n') {break;}
    }

    while(buf[start] == '\0' && start < *offset) {start++;}

    *lineptr = &buf[start];
    lsize = *offset - start;

    if(*offset == *rsize)
    {
        *offset = 0;
        *rsize = 0;
    }
   
    return lsize;
}

static inline void _rdstart(struct file_io_t * fio_arg, char * buf, uint32_t bufsize)
{
    if((fio_arg->sqe = io_uring_get_sqe(&fio_arg->ring)) != NULL)
    {
        io_uring_prep_read(fio_arg->sqe, fio_arg->logfile_fd, buf, bufsize, fio_arg->offset);
        if(io_uring_submit(&fio_arg->ring) < 0)
        {
            fio_arg->sqe = NULL;
        }
    }  
}

static inline bool _rdawait(struct file_io_t * fio_arg, char * buf, uint32_t bufsize, uint32_t * size)
{
    fio_arg->sqe = NULL;
    if(io_uring_wait_cqe(&fio_arg->ring, &fio_arg->cqe) < 0 || fio_arg->cqe->res < 0)
    {
        return false;
    }

    uint32_t rsize = (uint32_t) fio_arg->cqe->res;
    io_uring_cqe_seen(&fio_arg->ring, fio_arg->cqe);

    if((*size = rsize))
    {

        while(*size > 0)
        {
            if(buf[((*size)) - 1] == '\n') {break;}
            (*size)--;
        } 

        fio_arg->offset += *size;

        return rsize == bufsize;

    }

    return false;
}

inline int uring_getline(struct file_io_t * fio_arg, char ** lineptr)
{

    if(fio_arg == NULL || lineptr == NULL)
    {
        return IO_IPC_NULLPTR_ERR;
    }

    if(fio_arg->scnd_buf)
    {
        if(fio_arg->rsize2 > 0)
        {
            return _rdline(&fio_arg->offset2, &fio_arg->rsize2, fio_arg->fbuf2, lineptr);
        }

        if(fio_arg->sqe != NULL)
        {
            if(_rdawait(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1), &fio_arg->rsize1))
            {
                _rdstart(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2));
            }
        }   

        else 
        {
            _rdstart(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2));
            if(_rdawait(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2), &fio_arg->rsize2))
            {
                _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));
            }

            if(fio_arg->rsize2 > 0)
            {
                return _rdline(&fio_arg->offset2, &fio_arg->rsize2, fio_arg->fbuf2, lineptr);
            }

            return 0;

        }

        if(fio_arg->rsize1 > 0)
        {
            fio_arg->scnd_buf = false;
            return _rdline(&fio_arg->offset1, &fio_arg->rsize1, fio_arg->fbuf1, lineptr);
        }

        return 0;

    }
    else 
    {
        if(fio_arg->rsize1 > 0)
        {
            return _rdline(&fio_arg->offset1, &fio_arg->rsize1, fio_arg->fbuf1, lineptr);
        }

        if(fio_arg->sqe != NULL)
        {
            if(_rdawait(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2), &fio_arg->rsize2))
            {
                _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));
            }
        }   

        else 
        {
            _rdstart(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1));

            if(_rdawait(fio_arg, fio_arg->fbuf1, sizeof(fio_arg->fbuf1), &fio_arg->rsize1))
            {
                _rdstart(fio_arg, fio_arg->fbuf2, sizeof(fio_arg->fbuf2));
            }

            if(fio_arg->rsize1 > 0)
            {
                return _rdline(&fio_arg->offset1, &fio_arg->rsize1, fio_arg->fbuf1, lineptr);
            }

            return 0;

        }

        if(fio_arg->rsize2 > 0)
        {
            fio_arg->scnd_buf = true;
            return _rdline(&fio_arg->offset2, &fio_arg->rsize2, fio_arg->fbuf2, lineptr);
        }

        return 0;
    }

}

int uring_getlines(struct file_io_t * fio_arg, struct iovec * iovecs, uint16_t vsize, uint16_t bufsize)
{

    if(iovecs == NULL){return IO_IPC_ARG_ERR;}

    int retval;
    uint16_t read = 0;
    char * line;

    for(uint16_t i = 0; i < vsize; i++)
    {
        if((retval = uring_getline(fio_arg, &line)) < 0)
        {
            return retval;
        }

        if(retval > 0)
        {
            if(retval <= bufsize && memcpy(iovecs[i].iov_base, line, retval) != NULL)
            {
                iovecs[i].iov_len = retval;
                read++;
            }
                     
            continue;
        }

        if(retval == 0)
        {
            return read;
        }

    }

    return read;
}
