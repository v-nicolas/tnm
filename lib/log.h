/*
 *  Author: Vilmain Nicolas <nicolas.vilmain@gmail.com>
 *
 *  This file is part of TNM.
 *
 *  tnm is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  tnm is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with tnm. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LIB_LOG_H
#define LIB_LOG_H

#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifndef NDEBUG
# define DEBUG(...)				\
    do {					\
	fprintf(stderr, "%s: %s %s(%d): ",	\
		progname, __FILE__,		\
		__func__, __LINE__);		\
	fprintf(stderr, __VA_ARGS__);		\
    } while (0)
#else
# define DEBUG(...) { /* nop */ }
#endif /* DEBUG */

#define STRERRNO (strerror(errno))

#ifndef ATTR_FMT_PRINTF
# define ATTR_FMT_PRINTF(y, z) __attribute__((format(printf, y, z)))
#endif /* ATTR_FMT_PRINTF */

enum log_output_list {
    LOG_OUTPUT_ERR,
    LOG_OUTPUT_INFO,
};

void log_init_default_output(void);
void log_free(void);
int log_set_output(int type, const char *path);
void fatal(const char *fmt, ...) ATTR_FMT_PRINTF(1, 2);
void err(const char *fmt, ...) ATTR_FMT_PRINTF(1, 2);
char * dump_err(const char *fmt, ...) ATTR_FMT_PRINTF(1, 2);
void warn(const char *fmt, ...) ATTR_FMT_PRINTF(1, 2);
void info(const char *fmt, ...) ATTR_FMT_PRINTF(1, 2);

extern const char *progname;

#endif /* not have LIB_LOG_H */
