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
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include "icmp.h"

/* version 4 */
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
/* version 6 */
#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129

static uint16_t ic_seqnum = 0;

static uint16_t ic_inc_seqnum(void);
static uint16_t ic_cksum(const uint16_t *p, size_t len);

void
icmp_make_hdr(struct icmphdr *ic, int v)
{
    ic->type = ICMP_ECHO_REQUEST;
    if (v == AF_INET6) {
        ic->type = ICMPV6_ECHO_REQUEST;
    }
    ic->code = 0;
    ic->id = htons((uint16_t) getpid());
    ic->sequence = ic_inc_seqnum();
    ic->checksum = 0;
    ic->checksum = ic_cksum((uint16_t *) ic, sizeof(struct icmphdr));
}

int
icmp_is_echo_reply(void *pkt, size_t pkt_size, uint16_t seq_num, int ipversion)
{
    size_t ip_size;
    struct ip *ip = NULL;
    struct icmphdr *ic = NULL;
    
    if (ipversion == AF_INET) {
        if (pkt_size < sizeof(struct iphdr)) {
            return -1;
        }
	
        ip = pkt;
        ip_size = (size_t) ip->ip_hl * 4;
        if (pkt_size < (ip_size + sizeof(struct icmphdr))) {
            return -1;
        }
        ic = (void*)(((char*)pkt) + ip_size);
        if (ic->type != ICMP_ECHO_REPLY || ic->sequence != seq_num) {
            return -1;
         }
    } else {
        if (pkt_size < sizeof(struct icmphdr)) {
            return -1;
        }
        ic = pkt;
        if (ic->type != ICMPV6_ECHO_REPLY || ic->sequence != seq_num) {
            return -1;
        }
    }
    return 0;
}

static uint16_t
ic_inc_seqnum(void)
{
    uint16_t ret;
    
    if (ic_seqnum == 0xffff) {
        ic_seqnum = 0x0001;
    }
    ret = htons(ic_seqnum++);
    return ret;
}

static uint16_t
ic_cksum(const uint16_t *p, size_t len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= sizeof(*p);
    }
    if (len == 1) {
        sum += (uint16_t) *((const uint8_t *) p);
    }
    
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t) ~sum;
}
