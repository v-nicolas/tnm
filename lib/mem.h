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

#ifndef LIB_MEM_H
#define LIB_MEM_H

#include <sys/types.h>

#define ATTR_AUTOFREE __attribute__((cleanup(xfreeauto)))

void * xmalloc(size_t size);
void *xcalloc(size_t size);
void xfree(void *p);
void * xrealloc(void *p, size_t size);
void xfreeauto(void *p);
char * xstrdup(const char *src);

#endif /* not have LIB_MEM_H */
