/*
 *  Author: Vilmain Nicolas <nicolas.vilmain@gmail.com>
 *
 *  This file is part of lib sbuf.
 *
 *  lib sbuf is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  lib sbuf is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with lib sbuf.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif /* !_GNU_SOURCE */

#ifndef __GNUC__
# define __GNUC__
#endif /* !__GNUC__ */

#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "sbuf.h"
#include "sbuf_mutex.h"

#ifndef SBUF_ALLOC_SIZE
# define SBUF_ALLOC_SIZE 128
#elif SBUF_ALLOC_SIZE < 1
# error "sbuf: Invalid allocate size !"
#endif /* !SBUF_ALLOC_SIZE */

#define SBUF_RESIZE(ptr, newsize)               \
    do {                                        \
        ptr = realloc(ptr, newsize);            \
        if (newsize && !ptr)                    \
            exit(EXIT_FAILURE);                 \
    } while (0)

#define SBUF_SAFE_CALL(ret, func, ...)          \
    do {                                        \
        sbuf_lock(str);                         \
        ret = func(__VA_ARGS__);		\
        sbuf_unlock(str);                       \
    } while(0)

enum sbuf_read_file_errors {
    SBUF_ERR_OPEN = 1,
    SBUF_ERR_READ = 2,
};

static int sbuf_add_unsafe(struct sbuf *str, const char *addstr);
static int sbuf_add_to_offset_unsafe(struct sbuf *str,
				     size_t offset,
                                     const char *addstr);
static long sbuf_search_unsafe(struct sbuf *str, const char *substr, long off);
static int sbuf_rm_after_offset_unsafe(struct sbuf *str,
				       size_t rm_size,
                                       size_t offset);
static void sbuf_rm_memmove_buffer(struct sbuf *str,
				   size_t offset,
                                   const char *strmove);
static long sbuf_replace_unsafe(struct sbuf *str,
				const char *oldstr,
				const char *newstr,
				long off);


void
sbuf_init(struct sbuf *str)
{
    str->buf = NULL;
    str->offset = 0;
    str->size = 0;
    sbuf_mutex_init(str);
}

int
sbuf_add(struct sbuf *str, const char *addstr)
{
    int ret;

    SBUF_SAFE_CALL(ret, sbuf_add_unsafe, str, addstr);
    return ret;
}

static int
sbuf_add_unsafe(struct sbuf *str, const char *addstr)
{
    size_t addlen;

    if (!addstr || !addstr[0]) {
        return 0;
    }

    addlen = strlen(addstr);
    if ((str->offset + addlen) >= str->size) {
        str->size += SBUF_ALLOC_SIZE;
        if (addlen >= SBUF_ALLOC_SIZE) {
            str->size += addlen;
	}
        SBUF_RESIZE(str->buf, str->size);
    }

    memcpy((str->buf + str->offset), addstr, addlen);
    str->offset += addlen;
    str->buf[str->offset] = 0;
    return 0;
}

int
sbuf_vadd(struct sbuf *str, const char *fmt, ...)
{
    int nwrite;
    char *buf;
    va_list va;

    va_start(va, fmt);
    nwrite = vasprintf(&buf, fmt, va);
    va_end(va);

    if (nwrite > 0) {
        sbuf_add(str, buf);
    }

    if (buf) {
        free(buf);
    }
    
    return nwrite;
}

int
sbuf_add_to_offset(struct sbuf *str, size_t offset, const char *addstr)
{
    int ret;

    SBUF_SAFE_CALL(ret, sbuf_add_to_offset_unsafe, str, offset, addstr);
    return ret;
}

static int
sbuf_add_to_offset_unsafe(struct sbuf *str, size_t offset, const char *addstr)
{
    size_t addlen;

    if (offset > str->offset) {
	offset = str->offset;
    }
    
    addlen = strlen(addstr);
    if (str->size <= (str->offset + addlen)) {
        str->size += (addlen + SBUF_ALLOC_SIZE);
        SBUF_RESIZE(str->buf, str->size);
    }

    memmove((str->buf + (offset + addlen)),
            (str->buf + offset),
            (str->offset - offset));

    if (addlen) {
        memcpy((str->buf + offset), addstr, addlen);
        str->offset += addlen;
    }

    str->buf[str->offset] = 0;
    return 0;
}

int
sbuf_set_size(struct sbuf *str, size_t newsize)
{
    if ((ssize_t) newsize < 1) {
	return -1;
    }
    
    sbuf_lock(str);
    if (newsize <= str->offset) {
        sbuf_unlock(str);
        return -1;
    }
    
    SBUF_RESIZE(str->buf, newsize);
    str->size = newsize;
    sbuf_unlock(str);

    return 0;
}

size_t
sbuf_len(struct sbuf *str)
{
    size_t len;

    sbuf_lock(str);
    len = str->offset;
    sbuf_unlock(str);

    return len;
}

long
sbuf_search(struct sbuf *str, const char *substr)
{
    long ret;

    SBUF_SAFE_CALL(ret, sbuf_search_unsafe, str, substr, 0);
    return ret;
}

static long
sbuf_search_unsafe(struct sbuf *str, const char *substr, long off)
{
    const char *ret;

    if (off > (long) str->offset) {
	return -1;
    }
    
    ret = strstr((str->buf + off), substr);
    if (ret == NULL) {
        return -1;
    }
    
    return ret - str->buf;
}

#define SBUF_TO(transform, str)                     \
    char *sptr;                                     \
    sbuf_lock(str);                                 \
    for (sptr = str->buf; *sptr; sptr++)            \
        *sptr = (char) to##transform((int) *sptr);  \
    sbuf_unlock(str)

void
sbuf_to_lower(struct sbuf *str)
{
    SBUF_TO(lower, str);
}

void
sbuf_to_upper(struct sbuf *str)
{
    SBUF_TO(upper, str);
}

void
sbuf_trim_blank(struct sbuf *str)
{
    ssize_t i;

    sbuf_lock(str);
    if (!str->offset) {
        sbuf_unlock(str);
        return;
    }

    i = (ssize_t) str->offset - 1;

#define sbuf_isblank(c) (isblank(c) || c == '\n')
    if (sbuf_isblank(str->buf[i])) {
	do {
	    str->buf[i] = 0;
	    i--;
	} while (i > -1 && sbuf_isblank(str->buf[i]));

	str->offset = (size_t) i + 1;
    }

    sbuf_unlock(str);
}

int
sbuf_trim_char(struct sbuf *str, char c)
{
    int ret;
    ssize_t i;
    
    sbuf_lock(str);
    if (c == 0 || str->offset == 0) {
        sbuf_unlock(str);
	return -1;
    }

    ret = -1;
    i = (ssize_t) str->offset - 1;

    if (str->buf[i] == c) {
	ret = 0;
	    
	do {
	    str->buf[i] = 0;
	    i--;
	} while (i > -1 && str->buf[i] == c);
	
	str->offset = (size_t) i + 1;
    }
    
    sbuf_unlock(str);
    return ret;
}

void
sbuf_rm(struct sbuf *str, size_t rm_size)
{
    size_t i;

    if (!rm_size)
        return;

    sbuf_lock(str);
    if (str->offset) {
        i = str->offset;

	do {
            str->buf[--i] = 0;
        } while (--rm_size && i);

	str->offset = i;
    }
    sbuf_unlock(str);
}

int
sbuf_rm_before_offset(struct sbuf *str, size_t rm_size, size_t offset)
{
    long i;
    char *save;

    if (rm_size < 1) {
        return 0;
    }

    sbuf_lock(str);
    if (offset > str->offset) {
	offset = str->offset;
    }

    i = (long) (offset - rm_size);
    if (i < 0) {
        i = 0;
    }

    save = &str->buf[offset];
    sbuf_rm_memmove_buffer(str, (size_t) i, save);
    sbuf_unlock(str);
    return 0;
}

int
sbuf_rm_after_offset(struct sbuf *str, size_t rm_size, size_t offset)
{
    int ret;

    if (!rm_size) {
        return 0;
    }
    
    SBUF_SAFE_CALL(ret, sbuf_rm_after_offset_unsafe, str, rm_size, offset);
    return ret;
}

static int
sbuf_rm_after_offset_unsafe(struct sbuf *str, size_t rm_size, size_t offset)
{
    size_t i;
    char *save;

    if (offset > str->offset) {
        return -1;
    }

    i = offset + rm_size;
    if (i >= str->offset) {
        i = str->offset;
    }

    save = &str->buf[i];
    sbuf_rm_memmove_buffer(str, offset, save);
    
    return 0;
}

static void
sbuf_rm_memmove_buffer(struct sbuf *str, size_t offset, const char *strmove)
{
    size_t movelen;

    str->offset = offset;
    movelen = strlen(strmove);

    if (movelen) {
        memmove((str->buf + offset), strmove, movelen);
        str->offset += movelen;
    }
    
    str->buf[str->offset] = 0;
}

long
sbuf_replace(struct sbuf *str, const char *oldstr, const char *newstr)
{
    long ret;

    if (!oldstr || !oldstr[0] || !newstr) {
        return -1;
    }

    SBUF_SAFE_CALL(ret, sbuf_replace_unsafe, str, oldstr, newstr, 0);
    return ret;
}

static long
sbuf_replace_unsafe(struct sbuf *str, const char *oldstr,
		    const char *newstr, long off)
{
    long offset;

    offset = sbuf_search_unsafe(str, oldstr, off);
    if (offset < 0) {
        return -1;
    }

    if (sbuf_rm_after_offset_unsafe(str, strlen(oldstr), (size_t) offset) < 0) {
        return -1;
    }

    sbuf_add_to_offset_unsafe(str, (size_t) offset, newstr);
    return offset + (long) strlen(newstr);
}

void
sbuf_replace_all(struct sbuf *str, const char *oldstr, const char *newstr)
{
    long off;
    
    if (!oldstr || !oldstr[0] || !newstr)
        return;

    off = 0;
    sbuf_lock(str);

    do {
        off = sbuf_replace_unsafe(str, oldstr, newstr, off);
    } while (off != -1);
    
    sbuf_unlock(str);
}

int
sbuf_read_file(struct sbuf *str, const char *path)
{
    int fd;
    ssize_t nread;
    char buffer[1024];

    if ((fd = open(path, O_RDONLY)) < 0) {
        return -SBUF_ERR_OPEN;
    }

    sbuf_lock(str);
    do {
        nread = read(fd, buffer, 1023);
        if (nread < 0) {
            (void) close(fd);
            sbuf_unlock(str);
            return -SBUF_ERR_READ;
        }
        else if (nread > 0) {
            buffer[nread] = 0;
            sbuf_add_unsafe(str, buffer);
        }
    } while (nread == 1023);
    sbuf_unlock(str);
    close(fd);
    return 0;
}

const char *
sbuf_rdfile_get_func_fail(int errnum)
{
    if (errnum == -SBUF_ERR_OPEN) {
        return "open";
    }
    else if (errnum == -SBUF_ERR_READ) {
        return "read";
    }
    
    return "nop";
}

char *
sbuf_string_copy(struct sbuf *str)
{
    char *duplicat;

    SBUF_SAFE_CALL(duplicat, strdup, str->buf);
    return duplicat;
}

int
sbuf_has_prefix(struct sbuf *str, const char *prefix)
{
    return strncmp(str->buf, prefix, strlen(prefix));
}

int
sbuf_has_suffix(struct sbuf *str, const char *suffix)
{
    size_t len;

    len = strlen(suffix);
    if (str->offset < len) {
	return -1;
    }
    
    return strcmp((str->buf + (str->offset - len)), suffix);
}

void
sbuf_reset(struct sbuf *str)
{
    sbuf_lock(str);

    if (str->buf) {
        memset(str->buf, 0, str->size);
    }
    
    str->offset = 0;
    sbuf_unlock(str);
}

void
sbuf_free(struct sbuf *str)
{
    sbuf_reset(str);
    if (str->buf) {
        free(str->buf);
        str->buf = NULL;
    }
    sbuf_mutex_destroy(str);
}
