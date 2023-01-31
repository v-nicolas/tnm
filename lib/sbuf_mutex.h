/*
 *  Author: Vilmain Nicolas <nicolas.vilmain@gmail.com>
 *
 *  This file is part of lib sbuf.
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

#ifndef __SBUF_MUTEX_H__
#define __SBUF_MUTEX_H__

#ifdef SBUF_THREAD_SAFE

static inline void sbuf_lock(struct sbuf *s) {
    pthread_mutex_lock(&s->mutex);
}

static inline void sbuf_unlock(struct sbuf *s) {
    pthread_mutex_unlock(&s->mutex);
}

static inline void sbuf_mutex_init(struct sbuf *s) {
    pthread_mutex_init(&s->mutex, NULL);
}

static inline void sbuf_mutex_destroy(struct sbuf *s) {
    pthread_mutex_destroy(&s->mutex);
}

#else

# define __SBUF_UNUSED __attribute__((unused))
static inline void sbuf_lock(struct sbuf *s __SBUF_UNUSED) { /* nothing */ }
static inline void sbuf_unlock(struct sbuf *s  __SBUF_UNUSED) { /* nothing */ }
static inline void sbuf_mutex_init(struct sbuf *s __SBUF_UNUSED) { /* nothing */ }
static inline void sbuf_mutex_destroy(struct sbuf *s __SBUF_UNUSED) { /* nothing */ }

#endif /* SBUF_THREAD_SAFE */

#endif /* not have __SBUF_MUTEX_H__ */
