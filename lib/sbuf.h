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

#ifndef __SBUF_H__
#define __SBUF_H__

#include <stddef.h>

#define SBUF_VERSION_MAJOR 1.0
#define SBUF_VERSION_MINOR 1

#ifdef SBUF_THREAD_SAFE
# include <pthread.h>
# define SBUF_INIT {0, 0, NULL, PTHREAD_MUTEX_INITIALIZER}
#else
# define SBUF_INIT {0, 0, NULL}
#endif /* sbuf_THREAD_SAFE */

#define SBUF_CHK_FMT(y,z) __attribute__((format(printf, y, z)))

typedef struct sbuf {
    size_t size;
    size_t offset;
    char *buf;
#ifdef SBUF_THREAD_SAFE
    pthread_mutex_t mutex;
#endif /* SBUF_THREAD_SAFE */
} sbuf_t;

void sbuf_init(struct sbuf *str);
int sbuf_add(struct sbuf *str, const char *addstr);
int sbuf_vadd(struct sbuf *str, const char *fmt, ...) SBUF_CHK_FMT(2, 3);
int sbuf_add_to_offset(struct sbuf *str, size_t offset, const char *addstr);
int sbuf_set_size(struct sbuf *str, size_t newsize);
size_t sbuf_len(struct sbuf *str);
long sbuf_search(struct sbuf *str, const char *substr);
void sbuf_to_lower(struct sbuf *str);
void sbuf_to_upper(struct sbuf *str);
void sbuf_trim_blank(struct sbuf *str);
int sbuf_trim_char(struct sbuf *str, char c);
void sbuf_rm(struct sbuf *str, size_t rm_size);
int sbuf_rm_before_offset(struct sbuf *str, size_t rm_size, size_t offset);
int sbuf_rm_after_offset(struct sbuf *str, size_t rm_size, size_t offset);
long sbuf_replace(struct sbuf *str, const char *oldstr, const char *newstr);
void sbuf_replace_all(struct sbuf *str, const char *oldstr, const char *newstr);
int sbuf_read_file(struct sbuf *str, const char *path);
const char * sbuf_rdfile_get_func_fail(int errnum);
char * sbuf_string_copy(struct sbuf *str);
int sbuf_has_prefix(struct sbuf *str, const char *prefix);
int sbuf_has_suffix(struct sbuf *str, const char *suffix);
void sbuf_reset(struct sbuf *str);
void sbuf_free(struct sbuf *str);

#endif /* not have __SBUF_H__ */
