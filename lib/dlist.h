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

#ifndef LIB_DLIST_H
#define LIB_DLIST_H

/*
 * r = root
 * c = chunk
 */

#define LIST_FOREACH(r, c) for (c = r; c; c = c->next)

#define SLIST_LINK_HEAD(r, c)			\
    do {					\
	c->next = NULL;				\
	if (r == NULL) {			\
	    r = c;				\
	} else {				\
	    c->next = r;			\
	    r = c;				\
	}					\
    } while (0);

#define SLIST_LINK_TAIL(r, c)			\
    do {					\
	c->next = NULL;				\
	if (r == NULL) {			\
	    r = c;				\
	} else {				\
	    typeof(r) _sListPtr = r;		\
	    while (_sListPtr->next) {		\
		_sListPtr = _sListPtr->next;	\
	    }					\
	    _sListPtr->next = c;		\
	}					\
    } while (0);

#define DLIST_LINK(r, c)			\
    do {					\
	c->prev = NULL;				\
	c->next = NULL;				\
	if (r == NULL) {			\
	    r = c;				\
	} else {				\
	    c->next = r;			\
	    r->prev = c;			\
	    r = c;				\
	}					\
    } while (0);

#define DLIST_UNLINK(r, c)			\
    do {					\
	if (r == c) {				\
	    r = r->next;			\
	    if (r != NULL) {			\
		r->prev = NULL;			\
	    }					\
	} else {				\
	    c->prev->next = c->next;		\
	    if (c->next != NULL) {		\
		c->next->prev = c->prev;	\
	    }					\
	}					\
    } while (0);

#endif /* not have LIB_DLIST_H */
