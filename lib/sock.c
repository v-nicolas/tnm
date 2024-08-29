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

#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#ifdef HAVE_SSL
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/err.h>
#endif /* HAVE_SSL */

#include "sock.h"

#include "log.h"
#include "mem.h"
#include "file_utils.h"

static int sock_set_non_block(int sockfd);
static int socku_set_path(const char *path, struct sockaddr_un *un);
static int sock_eval_res(ssize_t res);
#ifdef HAVE_SSL
static const char *ssl_get_err(void);
#endif /* HAVE_SSL */

int
socku_server_create(const char *path)
{
    int fdserv;
    socklen_t len;
    struct sockaddr_un un;

    xunlink(path);
    memset(&un, 0, sizeof(struct sockaddr_un));
    if (socku_set_path(path, &un) < 0) {
	return -1;
    }

    fdserv = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fdserv < 0) {
        err("socku_socket: %s\n", STRERRNO);
        return -1;
    }

    un.sun_family = AF_UNIX;
    len = sizeof(struct sockaddr_un);
    
    if (bind(fdserv, (struct sockaddr *)&un, len) < 0) {
        err("socku_bind: %s\n", STRERRNO);
        (void) xclose(fdserv);
        return -1;
    }

    if (listen(fdserv, 12) < 0) {
        err("socku_listen: %s\n", STRERRNO);
        (void) xclose(fdserv);
	xunlink(path);
        return -1;
    }
    
    if (sock_set_non_block(fdserv) < 0) {
	(void) xclose(fdserv);
	xunlink(path);
	return -1;
    }

    return fdserv;
}

int
sock_server_create(const char *bind_addr, int port, int option)
{
    int fd;
    int opt;
    struct sock sock;

    sock.type = SOCK_STREAM;
    sock.proto = 0;
    sock.port = port;
    sock.family = AF_UNSPEC;
    
    if (bind_addr == NULL) {
	if (option == SOCK_OPT_IPv4_ONLY) {
	    sock.family = AF_INET;
	} else {
	    sock.family = AF_INET6;
	}
    }

    if (sock_resolv_addr(bind_addr, &sock) < 0) {
	return -1;
    }
    DEBUG("HTTP server bind address: %s\n", sock.straddr);
    
    fd = socket(sock.family, sock.type, sock.proto);
    if (fd < 0) {
	err("socket: %s\n", STRERRNO);
	return -1;
    }

    opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
	err("setsockopt SO_REUSEADDR->true: %s\n", STRERRNO);
	goto error;
    }

    if (option == SOCK_OPT_IPv6_ONLY) {
	opt = 1;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
		       (char*)&opt, sizeof(opt)) < 0) {
	    err("setsockopt IPV6_ONLY->true: %s\n", STRERRNO);
	    goto error;
	}
    }
    
    if (bind(fd, (struct sockaddr *)&sock.addr, sock.addrlen) < 0) {
	err("bind: %s\n", STRERRNO);
	goto error;
    }
    
    if (listen(fd, 64) < 0) {
	err("bind: %s\n", STRERRNO);
	goto error;
    }
    
    return fd;

error:
    close(fd);
    return -1;
}

static int
sock_set_non_block(int sockfd)
{
    int flags;
    
    flags = fcntl(sockfd, F_GETFL);
    if (flags < 0) {
        err("fcntl: get flags: %s\n", STRERRNO);
        return -1;
    }
    
    if (fcntl(sockfd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
        err("fcntl: set non block: %s\n", STRERRNO);
        return -1;
    }

    return 0;
}

int
socku_client_create(const char *path)
{
    int fd;
    struct sockaddr_un un;

    memset(&un, 0, sizeof(un));
    if (socku_set_path(path, &un) < 0) {
	return -1;
    }

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        err("socku_socket: %s\n", STRERRNO);
        return -1;
    }

    un.sun_family = AF_UNIX;
    if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
        err("socku_connect: %s\n", STRERRNO);
        (void) xclose(fd);
        return -1;
    }

    return fd;
}

void
socku_close(int fd, char *path)
{
    (void) xclose(fd);
    xunlink(path);
    xfree(path);
}

static int
socku_set_path(const char *path, struct sockaddr_un *un)
{
    unsigned long max;
    char buf[15];

    max = sizeof(un->sun_path) - 1;
    DEBUG("sock unhix path max len: %lu\n", max);
    
    if (path == NULL || *path == 0) {
	err("socku path is empty.\n");
	return -1;
    }
    if (strlen(path) > max) {
	memset(buf, 0, sizeof(buf));
	strncpy(buf, path, sizeof(buf) - 5);
	strncat(buf, "...", sizeof(buf) - strlen(buf) - 1);
        err("socku path <%s> is too big (max len: %lu)\n", buf, max);
        return -1;
    }
    
    strncpy(un->sun_path, path, max);
    return 0;
}

int
sock_connect(struct sock *sock, int timeout)
{
    int ret;
    int error;
    int flags;
    socklen_t len;
    fd_set fdset;
    struct timeval tv;

    sock->fd = socket(sock->family, sock->type, sock->proto);
    if (sock->fd == -1) {
        err("socket: %s\n", STRERRNO);
        return -1;
    }

    flags = fcntl(sock->fd, F_GETFL, 0);
    if (flags == -1) {
        err("fcntl GETFL: <%s>: %s\n", sock->straddr, STRERRNO);
        goto conn_fail;
    }

    if (fcntl(sock->fd, F_SETFL, (flags | O_NONBLOCK)) < 0) {
        err("fcntl SETFL (unblock) : <%s>: %s\n", sock->straddr, STRERRNO);
        goto conn_fail;
    }

    ret = connect(sock->fd, (struct sockaddr *)&sock->addr, sock->addrlen);
    if (ret == 0) {
        goto conn_success;
    }
    
    if (ret < 0 && errno != EINPROGRESS) {
        err("connect: %s\n", STRERRNO);
        goto conn_fail;
    }

    FD_ZERO(&fdset);
    FD_SET(sock->fd, &fdset);

    tv.tv_usec = 0;
    tv.tv_sec = timeout;
    
    ret = select(sock->fd + 1, NULL, &fdset, NULL, &tv);
    if (ret < 0) {
        err("select: %s\n", STRERRNO);
        goto conn_fail;
    }

    if (ret == 0) {
        warn("sock_connect: %s: timouted (%d)\n",
	     sock->straddr, timeout);
        xclose(sock->fd);
        return SOCK_RET_TIMEOUT;
    }
    
    if (ret > 0) {
        len = sizeof(error);
        if (getsockopt(sock->fd,
                       SOL_SOCKET,
                       SO_ERROR, &error, &len) < 0) {
            err("getsockopt: %s\n", STRERRNO);
            goto conn_fail;
        }

        if (error != 0) {
            err("getsockopt: SO_ERROR <%s>: %s\n",
		sock->straddr, strerror(error));
            xclose(sock->fd);
            return SOCK_RET_CONN_FAIL;
        }
    }

conn_success:
    if (fcntl(sock->fd, F_SETFL, flags) < 0) {
        err("fcntl SETFL (block): <%s>: %s\n", sock->straddr, STRERRNO);
        return SOCK_RET_ERR;
    }
    return SOCK_RET_SUCCESS;
    
conn_fail:
    xclose(sock->fd);
    return SOCK_RET_ERR;
}

int
sock_write(struct sock *sock, const void *buf, size_t bufsize)
{
    return sock_write_fd(sock->fd, buf, bufsize);
}

int
sock_write_fd(int fd, const void *buf, size_t bufsize)
{
    int ret;
    
    do {
        errno = 0;
        ret = (int) send(fd, buf, bufsize, 0);
    } while (ret == -1 && errno == EINTR);
    
    if (ret == -1) {
        err("send: %s\n", STRERRNO);
    }

    return ret;
}

int
sock_recvfrom(struct sock *sock, struct sock_recvfrom *r)
{
    int ret;
    socklen_t len;
    struct timeval tv;

    if (r->timeout > 0) {
	tv.tv_sec = r->timeout;
	tv.tv_usec = 0;
    
	if (setsockopt(sock->fd,
		       SOL_SOCKET,
		       SO_RCVTIMEO,
		       &tv, sizeof(tv)) < 0) {
	    err("setsockopt: SO_RECVTIMEO: %s\n", STRERRNO);
	    return SOCK_RET_ERR;
	}
    }

    memset(r->buf, 0, r->bufsize);
    len = sizeof(struct sockaddr_storage);
    do {
        ret = (int) recvfrom(sock->fd,
			     r->buf, (r->bufsize-1), 0,
			     (struct sockaddr *)&r->addr,
			     &len);
        DEBUG("recvfrom host: %s, recv %d bytes\n", sock->straddr, ret);
    } while (ret == -1 && errno == EINTR);

    if (ret < 0) {
        err("recvfrom: %s\n", STRERRNO);
        ret = sock_eval_res(ret);
    }

    return ret;
}

int
sock_read(struct sock *sock, void *buf, size_t bufsize, int timeout)
{
    return sock_read_fd(sock->fd, buf, bufsize, timeout);
}

int
sock_read_fd(int fd, void *buf, size_t bufsize, int timeout)
{
    int ret;
    struct timeval tv;

    if (timeout > 0) {
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
    
	if (setsockopt(fd,
		       SOL_SOCKET,
		       SO_RCVTIMEO,
		       (const char*) &tv, sizeof(tv)) < 0) {
	    err("sock_read: setsockopt SO_RCVTIMEO: %s\n", STRERRNO);
	    return -1;
	}
    }

    memset(buf, 0, bufsize);
    ret = (int) xrecv(fd, buf, (bufsize - 1));
    if (ret < 0) {
        err("recvfrom: %s\n", STRERRNO);
        ret = sock_eval_res(ret);
    }

    return ret;
}

char *
sock_read_alloc_timeout(int sockfd, unsigned int timeout)
{
    int ret;
    size_t size;
    ssize_t offset;
    void *data = NULL;
    fd_set fdset;
    struct timeval tv;

    size = 0;
    offset = 0;
    do {
        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);

        if (offset == 0) {
            tv.tv_sec = timeout;
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = 0;
            tv.tv_usec = 100;
        }

        ret = select((sockfd + 1), &fdset, NULL, NULL, &tv);
        if (ret < 0) {
            err("select: %s\n", STRERRNO);
            return NULL;
        }

        if (ret > 0 && FD_ISSET(sockfd, &fdset)) {
            size += RECV_ALLOC_SIZE;
            data = xrealloc(data, size);
            memset(((char *)data + offset), 0, RECV_ALLOC_SIZE);
            ret = xrecv(sockfd, ((char *)data + offset), (RECV_ALLOC_SIZE - 1));
            offset += ret;
        }

    } while (ret > 0);
    
    return data;
}

int
xrecv(int sockfd, void *buf, size_t bufsize)
{
    int ret;
    
    do {
        errno = 0;
        ret = (int) recv(sockfd, buf, bufsize, 0);
    } while (ret == -1 && errno == EINTR);

    if (ret == -1) {
        err("recv: %s\n", STRERRNO);
    }

    return ret;
}

void
sock_close(struct sock *sock)
{
    (void) xclose(sock->fd);
    sock->fd = -1;
}

static int
sock_eval_res(ssize_t res)
{
    int ret;
    
    ret = SOCK_RET_ERR;

    /* recvfrom:
     * POSIX.1 allows either error to be returned for this case,
     * and does not require these constants to have the same value,
     * so a portable application should check for both possibilities
     */
#if EAGAIN == EWOULDBLOCK
    if (res == EAGAIN) {
        ret =  SOCK_RET_TIMEOUT;
    }
#else 
    if (res == EAGAIN || res ==  EWOULDBLOCK) {
        ret =  SOCK_RET_TIMEOUT;
    }
#endif
    return ret;
}

int
sock_resolv_addr(const char *addr, struct sock *sock)
{
    int ret;
    char *pservice = NULL;
    struct addrinfo *res = NULL;
    struct addrinfo hints;
    char service[PORT_STR_LEN];

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = sock->family;
    hints.ai_protocol = sock->proto;
    hints.ai_socktype = sock->type;
    hints.ai_flags = AI_PASSIVE;

    if (sock->port != 0) {
	/* TODO: create test to pservice == NULL ans explan
	 * this why NULL is not a problem. */
        if (snprintf(service, (PORT_STR_LEN-1), "%d", sock->port) < 0) {
            err("Fail to convert port `%d' string\n", sock->port);
            return -1;
        }
        pservice = service;
    }
    
    ret = getaddrinfo(addr, pservice, &hints, &res);
    if (ret < 0) {
        err("getaddrinfo: %s\n", gai_strerror(ret));
        return -1;
    }

    if (sock->family == AF_UNSPEC) {
        sock->family = res->ai_family;
    }

    sock->addrlen = res->ai_addrlen;
    memcpy(&sock->addr, res->ai_addr, res->ai_addrlen);
    ret = sock_addr_to_str(sock->family, sock->straddr,  &sock->addr);
    freeaddrinfo(res);
    
    return ret;
}

int
sock_addr_to_str(int family, char *straddr, struct sockaddr_storage *addr)
{
    void *buf = NULL;
    struct sockaddr_in *ipv4 = NULL;
    struct sockaddr_in6 *ipv6 = NULL;
    
    memset(straddr, 0, INET6_ADDRSTRLEN);
    
    if (family == AF_INET) {
        ipv4 = (struct sockaddr_in *)addr;
        buf = &(ipv4->sin_addr);
    } else if (family == AF_INET6) {
        ipv6 = (struct sockaddr_in6 *)addr;
        buf = &(ipv6->sin6_addr);
    } else {
        err("Invalid IP family address.\n");
        return -1;
    }
    
    if (inet_ntop(family, buf, straddr,
                  (socklen_t) INET6_ADDRSTRLEN) == NULL) {
        err("Fail to convert ip in string.\n");
        return -1;
    }

    DEBUG("Convert ip `%s'\n", straddr);
    return 0;
}

#ifdef HAVE_SSL
int
ssl_init(struct sock *sock)
{
    const SSL_METHOD *meth= NULL;

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    meth = TLS_client_method();
    SSL_load_error_strings();

    /* Deprecated function with version 3.0 */
# if OPENSSL_VERSION_MAJOR < 3
    ERR_load_BIO_strings();
# endif /* OPENSSL_VERSION_MAJOR */
    
    SSL_load_error_strings();

    sock->ssl_ctx = SSL_CTX_new(meth);
    if (sock->ssl_ctx == NULL) {
	return -1;
    }
    return 0;    
}

void
ssl_free(struct sock *sock)
{
    ssl_close(sock);
    if (sock->ssl_ctx != NULL) {
	SSL_CTX_free(sock->ssl_ctx);
	sock->ssl_ctx = NULL;
    }
}

int
ssl_connect(struct sock *sock, int timeout)
{
    int ret;

    sock->ssl = SSL_new(sock->ssl_ctx);
    if (sock->ssl == NULL) {
	err("SSL_new: %s\n", ssl_get_err());
	return -1;
    }
    
    if (sock_connect(sock, timeout) != SOCK_RET_SUCCESS) {
	return -1;
    }

    SSL_set_SSL_CTX(sock->ssl, sock->ssl_ctx);
    SSL_set_fd(sock->ssl, sock->fd);
    ret = SSL_connect(sock->ssl);
    if (ret == -1) {
	err("SSL_connect: %s\n", ssl_get_err());
	return -1;
    }
    
    DEBUG("SSL: %s\n", SSL_get_cipher(sock->ssl));
    return 0;
}

int
ssl_read(struct sock *sock, void *buf, size_t bufsize, int timeout)
{
    int ret;
    struct timeval tv;
    
    if (timeout > 0) {
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
    
	if (setsockopt(SSL_get_fd(sock->ssl),
		       SOL_SOCKET,
		       SO_RCVTIMEO,
		       (const char*) &tv, sizeof(tv)) < 0) {
	    err("ssl_read: setsockopt SO_RCVTIMEO: %s\n", STRERRNO);
	    return -1;
	}
    }

    memset(buf, 0, bufsize);
    ret = SSL_read(sock->ssl, buf, (int) (bufsize-1));
    if (ret == -1) {
	err("SSL_write: %s\n", ssl_get_err());
    }
    return ret;
}

int
ssl_write(struct sock *sock, const void *buf, size_t bufsize)
{
    int ret;
    
    ret = SSL_write(sock->ssl, buf, (int) bufsize);
    if (ret == -1) {
	err("SSL_write: %s\n", ssl_get_err());
    }
    return ret;
}

void
ssl_close(struct sock *sock)
{
    (void) xclose(sock->fd);
    if (sock->ssl != NULL) {
	SSL_shutdown(sock->ssl);
	SSL_free(sock->ssl);
	sock->ssl = NULL;
    }
}

static const char *
ssl_get_err(void)
{
    unsigned long ssl_error;
    const char *error = NULL;
    
    ssl_error = ERR_get_error();
    if (ssl_error != 0) {
	error = ERR_error_string(ssl_error, 0);
    }
    if (error == NULL) {
	error = "ssl_unknown_error";
    }
    return error;
}
#endif /* HAVE_SSL */
