/*
 * libuuid: Generate new uuid..
 * Copyright (C) 2022 <nicolas.vilmain[at]gmail[dot]com>
 *
 *  This file is part of lib libuuid.
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "uuid.h"

static void uuid_gen(char *uuid, const unsigned char *seed);
static int uuid_get_seed(unsigned char *seed, unsigned int options);
static int uuid_seed_by_urandom(unsigned char *seed);
static int uuid_seed_by_timestamp(unsigned char *seed);
static void uuid_to_upper(char *uuid);

#define UUID_SEED_SIZE 16
#define UUID_DEV_URANDOM "/dev/urandom"

int
uuid_generate(char *uuid, unsigned int options)
{
    unsigned char seed[UUID_SEED_SIZE];

    memset(uuid, 0, UUID_SIZE);
    memset(seed, 0, UUID_SEED_SIZE);

    if (uuid_get_seed(seed, options) < 0) {
	return -1;
    }

    uuid_gen(uuid, seed);

    if ((options & UUID_GEN_OPT_UPPER)) {
	uuid_to_upper(uuid);
    }

    return 0;
}

static void
uuid_gen(char *uuid, const unsigned char *seed)
{
    int i;
    unsigned int offset;

    offset = 0;
    for (i = 0; i < UUID_SEED_SIZE; i++) {
	if (i == 4 || i == 6 || i == 8 || i == 10) {
	    uuid[offset] = '-';
	    offset++;
	}
	
	snprintf((uuid + offset), 3, "%02x", seed[i]);
	offset += 2;
    }
}

static int
uuid_get_seed(unsigned char *seed, unsigned int options)
{
    if ((options & UUID_GEN_OPT_URANDOM)) {
	if (uuid_seed_by_urandom(seed) < 0) {
	    return -1;
	}
    } else if ((options & UUID_GEN_OPT_TIMESTAMP)) {
	if (uuid_seed_by_timestamp(seed) < 0) {
	    return -1;
	}
    } else {
	if (uuid_seed_by_urandom(seed) < 0) {
	    if (uuid_seed_by_timestamp(seed) < 0) {
		return -1;
	    }
	}
    }
    
    return 0;
}

static int
uuid_seed_by_urandom(unsigned char *seed)
{
    int fd;
    ssize_t ret;
    
    fd = open(UUID_DEV_URANDOM, O_RDONLY);
    if (fd == -1) {
	return -1;
    }

    do {
	errno = 0;
	ret = read(fd, seed, UUID_SEED_SIZE);
    } while (ret == -1 && errno == EINTR);
    
    close(fd);

    if (ret == -1) {
	return -1;
    }

    return 0;
}

static int
uuid_seed_by_timestamp(unsigned char *seed)
{
    struct timeval tv;
    long int time_ms;
    
    if (gettimeofday(&tv, NULL) < 0) {
	return -1;
    }
    
    seed[0] = (unsigned char) (tv.tv_sec & 0xff);
    seed[1] = (unsigned char) (tv.tv_sec >> 8 & 0xff);
    seed[2] = (unsigned char) (tv.tv_sec >> 16 & 0xff);
    seed[3] = (unsigned char) (tv.tv_sec >> 24 & 0xff);

    seed[4] = (unsigned char) (tv.tv_usec & 0xff);
    seed[5] = (unsigned char) (tv.tv_usec >> 8 & 0xff);

    time_ms = (1000000 * tv.tv_sec + tv.tv_usec);

    seed[6] = (unsigned char) (time_ms & 0xff);
    seed[7] = (unsigned char) (time_ms >> 8 & 0xff);
    seed[8] = (unsigned char) (time_ms >> 16 & 0xff);
    seed[9] = (unsigned char) (time_ms >> 24 & 0xff);
    
    srand((unsigned int) time_ms);
    
    for (int i = 9; i < UUID_SEED_SIZE; i++) {
	seed[i] = (unsigned char) rand() & 0xff;
    }

    return 0;
}

static void
uuid_to_upper(char *uuid)
{
    do {
	*uuid = (char) toupper(*uuid);
	uuid++;
    } while (*uuid);
}
