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

#ifndef LIB_THREAD_H
#define LIB_THREAD_H

#include <pthread.h>

#define MUTEX_LOCK(m)         pthread_mutex_lock(m)
#define MUTEX_UNLOCK(m)       pthread_mutex_unlock(m)
#define MUTEX_INIT(m)         pthread_mutex_init(m, NULL)
#define MUTEX_DESTROY(m)      pthread_mutex_destroy(m)
#define THREAD_START(t,h,a)   pthread_create(t, NULL, h, a)

typedef pthread_t thread_t;
typedef pthread_mutex_t thread_mutex_t;

#endif /* !LIB_THREAD_H */
