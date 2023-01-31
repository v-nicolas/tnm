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

#ifndef LIB_ATTR_H
#define LIB_ATTR_H

#ifndef ATTR_UNUSED
# define ATTR_UNUSED __attribute__((unused))
#endif /* !ATTR_UNUSED */

#ifndef ATTR_PACKED
# define ATTR_PACKED __attribute__((packed))
#endif /* !ATTR_PACKED */

#ifndef ATTR_NORETURN
# define ATTR_NORETURN __attribute__((noreturn))
#endif /* !ATTR_NORETURN */

#ifndef ATTR_FMT_PRINTF
# define ATTR_FMT_PRINTF(y,z) __attribute__((format(printf, y, z)))
#endif /* ! ATTR_FMT_PRINTF */

#endif /* not have LIB_ATTR_H */
