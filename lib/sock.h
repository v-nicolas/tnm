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

#ifndef LIB_SOCK_H
#define LIB_SOCK_H

#include <sys/types.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef HAVE_SSL
# include <openssl/ssl.h>
#endif /* HAVE_SSL */

#define PORT_STR_LEN 6

#define PORT_HTTP 80
#define PORT_HTTPS 443

#ifndef RECV_ALLOC_SIZE
# define RECV_ALLOC_SIZE 512
#endif /* !RECV_ALLOC_SIZE */

enum socket_ret {
    SOCK_RET_SUCCESS    = 0,
    SOCK_RET_ERR        = -1,
    SOCK_RET_TIMEOUT    = -2,
    SOCK_RET_CONN_FAIL  = -2,
    SOCK_RET_HTTP_ERROR = -3,
};

enum socket_type {
    SOCK_TYPE_UNIX,
    SOCK_TYPE_TCP,
};

enum sock_srv_options {
    SOCK_OPT_IPv4_ONLY,
    SOCK_OPT_IPv6_ONLY,
    SOCK_OPT_IPv4_IPv6,
};

struct sock_recvfrom {
    int timeout;
    size_t bufsize;
    void *buf;
    struct sockaddr_storage addr;
};

struct sock {
    int fd;
    int port;
    int family;
    int type;
    int proto;
#ifdef HAVE_SSL
    SSL *ssl;
    SSL_CTX *ssl_ctx;
#endif /* HAVE_SSL */
    socklen_t addrlen;
    struct sockaddr_storage addr;
    char straddr[INET6_ADDRSTRLEN];

    int (*connect)(struct sock *, int timeout);
    int (*read)(struct sock*, void *buf, size_t bufsize, int timeout);
    int (*write)(struct sock*, const void *buf, size_t bufsize);
    void (*close)(struct sock*);
};

int socku_server_create(const char *path);
int sock_server_create(const char *bind_addr, int port, int option);
int socku_client_create(const char *path);
void socku_close(int fd, char *path);
int sock_connect(struct sock *sock, int timeout);
int sock_write(struct sock *sock, const void *buf, size_t bufsize);
int sock_write_fd(int fd, const void *buf, size_t bufsize);
int sock_read(struct sock *sock, void *buf, size_t bufsize, int timeout);
int sock_read_fd(int fd, void *buf, size_t bufsize, int timeout);
int sock_recvfrom(struct sock *sock, struct sock_recvfrom *r);
char * sock_read_alloc_timeout(int sockfd, unsigned int timeout);
int xrecv(int sockfd, void *buf, size_t bufsize);
void sock_close(struct sock *sock);
int sock_resolv_addr(const char *addr, struct sock *sock);
int sock_addr_to_str(int family, char *straddr, struct sockaddr_storage *addr);
int ssl_init(struct sock *sock);
void ssl_free(struct sock *sock);
int ssl_connect(struct sock *sock, int timeout);
int ssl_read(struct sock *sock, void *buf, size_t bufsize, int timeout);
int ssl_write(struct sock *sock, const void *buf, size_t bufsize);
void ssl_close(struct sock *sock);

#endif /* !LIB_SOCK_H */
