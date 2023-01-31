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

#ifndef LIB_FILE_UTILS_H
#define LIB_FILE_UTILS_H

#include <stdio.h>
#include <unistd.h>

#ifndef PATH_SIZE
# define PATH_SIZE 512
#endif /* !PATH_SIZE */

int xfclose(FILE *file);
FILE *xfopen(const char *path, const char *mode);
int xclose(int fd);
void xunlink(const char *path);
const char * files_access(const char *path1, const char *path2, int access_mode);

#endif /* !LIB_FILE_UTILS_H */
