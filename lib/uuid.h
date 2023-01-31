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

#ifndef LIB_UUID_H
#define LIB_UUID_H

#define UUID_SIZE 37

enum uuid_gen_options {
    UUID_GEN_OPT_UPPER       = (1 << 0),
    UUID_GEN_OPT_URANDOM     = (1 << 1),
    UUID_GEN_OPT_TIMESTAMP   = (1 << 2),
};

int uuid_generate(char *uuid, unsigned int options);

#endif /* not have LIB_UUID_H */
