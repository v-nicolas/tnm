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

#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "mem.h"

void *
xmalloc(size_t size)
{
    void *p = NULL;

    p = malloc(size);
    if (p == NULL) {
	fatal("memory exhausted.\n");
    }

    return p;
}

void *
xcalloc(size_t size)
{
    void *p = NULL;

    p = xmalloc(size);
    memset(p, 0, size);
    return p;
}

void
xfree(void *p)
{
    if (p != NULL) {
	free(p);
    }
}

void *
xrealloc(void *p, size_t size)
{
    if (size == 0) {
	xfree(p);
	return NULL;
    }

    if (p == NULL) {
	p = xmalloc(size);
    } else {
	p = realloc(p, size);
	if (p == NULL) {
	    fatal("realloc: memory exhausted\n");
	}
    }

    return p;
}

void
xfreeauto(void *p)
{
    if (p != NULL) {
	free(*(void **)p);
    }
}

char *
xstrdup(const char *src)
{
    char *dst = NULL;

    dst = strdup(src);
    if (dst == NULL) {
	fatal("strdup: memory exhausted\n");
    }

    return dst;
}

void
xstrredup(char **dst, const char *src)
{
    xfree(*dst);
    *dst = xstrdup(src);
}
