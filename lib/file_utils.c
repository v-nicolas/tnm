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

#include <unistd.h>
#include <sys/select.h>

#include "file_utils.h"
#include "log.h"

int
xfclose(FILE *file)
{
    if (file != NULL) {
	if (fclose(file) < 0) {
	    DEBUG("fclose: %s\n", STRERRNO);
	    return -1;
	}
    }
    return 0;
}

FILE *
xfopen(const char *path, const char *mode)
{
    FILE *file = NULL;

    file = fopen(path, mode);
    if (file == NULL) {
	err("fopen: <%s> %s\n", path, STRERRNO);
	return NULL;
    }
    return file;
}

int
xclose(int fd)
{
    if (fd > 1) {
	if (close(fd) < 0) {
	    warn("close: %s\n", STRERRNO);
	    return -1;
	}
    }
    return 0;
}

void
xunlink(const char *path)
{
    if (path == NULL || path[0] == 0) {
	return;
    }
#ifndef NDEBUG
    if (unlink(path) < 0) {
	warn("unlink <%s>: %s\n", path, STRERRNO);
    }
#else
    (void) unlink(path);
#endif
}

const char *
files_access(const char *path1, const char *path2, int access_mode)
{
    if (path1 != NULL && path1[0] != 0 && access(path1, access_mode) == 0) {
	return path1;
    }
    if (path2 != NULL && path2[0] != 0 && access(path2, access_mode) == 0) {
	return path2;
    }
    return NULL;
}
