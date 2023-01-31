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

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif /* _GNU_SOURCE */

#include <stdlib.h>
#include <stdarg.h>

#include "log.h"
#include "mem.h"
#include "attr.h"
#include "file_utils.h"

#define DUMP_ERR_FAIL "Dump error fail."

static FILE *err_output = NULL;
static FILE *info_output = NULL;

extern const char *progname;

void
log_init_default_output(void)
{
    err_output = stderr;
    info_output = stdout;
}

void
log_free(void)
{
    xfclose(err_output);
    xfclose(info_output);
}

int
log_set_output(int type, const char *path)
{
    int ret;

    ret = 0;
    if (type == LOG_OUTPUT_ERR) {
	xfclose(err_output);
	err_output = xfopen(path, "a");
	if (err_output == NULL) {
	    ret = -1;
	}
    } else {
	xfclose(info_output);
	info_output = xfopen(path, "a");
	if (info_output == NULL) {
	    ret = -1;
	}
    }

    return ret;
}

void ATTR_NORETURN
fatal(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(err_output, "%s: fatal: ", progname);
    vfprintf(err_output, fmt, ap);
    va_end(ap);
    exit(EXIT_FAILURE);
}

void
err(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(err_output, "%s: error: ", progname);
    vfprintf(err_output, fmt, ap);
    va_end(ap);
}

char *
dump_err(const char *fmt, ...)
{
    char *err = NULL;
    va_list ap;

    va_start(ap, fmt);
    if (vasprintf(&err, fmt, ap) < 0) {
	err = xstrdup(DUMP_ERR_FAIL);
    }
    va_end(ap);

    return err;
}

void
warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(err_output, "%s: warning: ", progname);
    vfprintf(err_output, fmt, ap);
    va_end(ap);
}

void
info(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    fprintf(info_output, "%s: info: ", progname);
    vfprintf(info_output, fmt, ap);
    va_end(ap);
}
