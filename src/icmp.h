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

#ifndef NM_ICMP_H
#define NM_ICMP_H

#include <inttypes.h>
#include <sys/types.h>
#include <asm/byteorder.h>

#define ICMPHDR_SIZE 8

struct icmphdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
};

void icmp_make_hdr(struct icmphdr *ic, int v);
int icmp_is_echo_reply(void *pkt, size_t pkt_size, uint16_t seq_num, int v);

#endif /* !NM_ICMP_H */
