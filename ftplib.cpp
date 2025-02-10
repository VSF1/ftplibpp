// enable > 2gb support (LFS)

#ifndef NOLFS
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <cstdint>
#include <string.h>
#include "ftplib.h"

#include <string>
#include <new>
#include <stdexcept>
#include <vector>

#ifndef NOSSL
// put ssl inside namespace to avoid naming colision
namespace openssl {
#include <openssl/ssl.h>
}
#ifndef _FTPLIB_SSL_CLIENT_METHOD_
#define _FTPLIB_SSL_CLIENT_METHOD_ openssl::TLS_client_method
#endif
#endif


#if defined(_WIN32)
    #include <windows.h>
    #include <winsock.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <arpa/inet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#if defined(_WIN32)
    #define SETSOCKOPT_OPTVAL_TYPE static_cast<const char *>
#else
    #define SETSOCKOPT_OPTVAL_TYPE static_cast<void *>
#endif

#if defined(_WIN32)
    #define net_read(x, y, z) ::recv(x, reinterpret_cast<char*>(y), z, 0)
    #define net_write(x, y, z) ::send(x, reinterpret_cast<char*>(y), z, 0)
    #define net_close closesocket
#else
    #define net_read ::read
    #define net_write ::write
    #define net_close ::close
#endif

#if defined(_WIN32)
    typedef int socklen_t;
#endif

#if defined(_WIN32)
    #define memccpy _memccpy
    #define strdup _strdup
#endif

inline const char *strnchr(const char *__s, char __c, int __n) {
    return static_cast<const char *>(::memchr(__s, __c, __n));
}

inline char *strnchr(char *__s, char __c, int __n) {
    return static_cast< char *>(::memchr(__s, __c, __n));
}

////////////////////////////////////////////////////////////////////////////////
/// socket values
////////////////////////////////////////////////////////////////////////////////
// #define SETSOCKOPT_OPTVAL_TYPE (void *)
#define FTPLIB_BUFSIZ 1024
#define ACCEPT_TIMEOUT 30

////////////////////////////////////////////////////////////////////////////////
/// io types
////////////////////////////////////////////////////////////////////////////////
#define FTPLIB_CONTROL 0
#define FTPLIB_READ 1
#define FTPLIB_WRITE 2

////////////////////////////////////////////////////////////////////////////////
/// internal classes
////////////////////////////////////////////////////////////////////////////////
#if 0
class plain_connection: public ftplib_connection_iface {
 public:
    plain_connection() {}
    virtual ~plain_connection() = default;

    int write(const void* data, size_t len, const ftphandle_t hdl, enum op_type wrt = op_data) override {
        return net_write(hdl->handle, data, len);
    }

    int read(void* data, size_t len, const ftphandle_t hdl, enum op_type rdt = op_data) override {
        return net_read(hdl->handle, data, len);
    }
};

#ifndef NOSSL
class ssl_connection: public plain_connection {
 public:
    ssl_connection() {}
    virtual ~ssl_connection() = default;

    int write(const void* data, size_t len, const ftphandle_t hdl, enum op_type wrt = op_data) override {
        if ((hdl->tlsdata && wrt == op_data) || (hdl->tlsctrl && wrt == op_ctl)) {
            return openssl::SSL_write(hdl->ssl, data, len);
        } else {
            return plain_connection::write(data, len, hdl, wrt);
        }
    }

    int read(void* data, size_t len, const ftphandle_t hdl, enum op_type rdt = op_data) override {
        if ((hdl->tlsdata && rdt == op_data) || (hdl->tlsctrl && rdt == op_ctl)) {
            return openssl::SSL_read(hdl->ssl, data, len);
        } else {
            return plain_connection::read(data, len, hdl, rdt);
        }
    }
};
#endif
#endif

static bool inline ends_with(const std::string &str, const std::string &ending) {
    if (ending.size() > str.size()) return false;
    return str.compare(str.size() - ending.size(), ending.size(), ending)== 0;
}

#if defined(_WIN32)
////////////////////////////////////////////////////////////////////////////////
/// win32 dll initializer
////////////////////////////////////////////////////////////////////////////////
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    // Returns TRUE on success, FALSE on failure
    return TRUE;
}
#endif

void ftplib::ssl_init_lib() {
#ifndef NOSSL
    static bool ssl_initialized = false;
    if (ssl_initialized) {
        return;
    }
    openssl::SSL_library_init();
    ssl_initialized = true;
#endif
}

void ftplib::ssl_init_handle() {
#ifndef NOSSL
    ftplib::ssl_init_lib();
    this->m_handle->ctx = openssl::SSL_CTX_new(_FTPLIB_SSL_CLIENT_METHOD_());
    openssl::SSL_CTX_set_verify(m_handle->ctx, SSL_VERIFY_NONE, NULL);
    this->m_handle->ssl = openssl::SSL_new(m_handle->ctx);
#endif
}


void ftplib::ssl_term_handle() {
#ifndef NOSSL
    if (this->m_handle->ssl != nullptr) {
        openssl::SSL_free(this->m_handle->ssl);
        this->m_handle->ssl = nullptr;
    }
    if (this->m_handle->ctx != nullptr) {
        openssl::SSL_CTX_free(this->m_handle->ctx);
        this->m_handle->ctx = nullptr;
    }
#endif
}

ftplib::ftplib() {
#if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(1, 1), &wsa)) {
        printf("WSAStartup() failed, %lu\n", (uint64_t)GetLastError());
    }
#endif

    this->m_handle = static_cast<ftphandle *>(std::calloc(1, sizeof(ftphandle)));
    if (this->m_handle == nullptr) {
        throw std::bad_alloc();
    }

    this->m_handle->buf = static_cast<char *>(std::malloc(FTPLIB_BUFSIZ));
    if (this->m_handle->buf == nullptr) {
        std::free(this->m_handle);
        this->m_handle = nullptr;
        throw std::bad_alloc();
    }
    this->clear_handle(this->m_handle);
#ifndef NOSSL
    this->ssl_init_handle();
#endif
}

ftplib::~ftplib() {
    if (this->m_handle != nullptr) {
        this->quit();
#ifndef NOSSL
        this->ssl_term_handle();
#endif
        if (this->m_handle->buf != nullptr) {
            std::free(this->m_handle->buf);
            this->m_handle->buf = nullptr;
        }
        // since the handle is a struct we must clear class members before calling free
        if (!m_handle->response.empty()) {
            m_handle->response.clear();
            m_handle->response.shrink_to_fit();
        }
        if (!m_handle->errormsg.empty()) {
            m_handle->errormsg.clear();
            m_handle->errormsg.shrink_to_fit();
        }

        std::free(this->m_handle);
        this->m_handle = nullptr;
    }
}

std::string ftplib::sprint_rest(off64_t offset) {
    return std::string("REST ") + std::to_string(offset);
}

int ftplib::socket_wait(ftphandle_t ctl) {
    fd_set fd, *rfd = nullptr, *wfd = nullptr;
    struct timeval tv;

    if (ctl->idlecb == nullptr) {
        return FTPLIB_E_NONE;
    }

  /*if ((ctl->dir == FTPLIB_CONTROL)
    || (ctl->idlecb == NULL)
    || ((ctl->idletime.tv_sec == 0)
    && //(ctl->idletime.tv_usec 0))
  return 1;*/

    if (ctl->dir == FTPLIB_WRITE) {
        wfd = &fd;
    } else {
        rfd = &fd;
    }

    FD_ZERO(&fd);
    int rv = FTPLIB_E_ERROR;
    do {
        FD_SET(ctl->handle, &fd);
        tv = ctl->idletime;
        rv = select(ctl->handle + 1, rfd, wfd, NULL, &tv);
        if (rv == -1) {
            ctl->ctrl->response = strerror(errno);
            this->update_errormsg(ctl->ctrl, "select");
            return FTPLIB_E_ERROR;
        } else if (rv > 0) {
            return FTPLIB_E_NONE;
        }
    } while ((rv = ctl->idlecb(ctl->cbarg)) == FTPLIB_E_NONE);
    return rv;
}

ssize_t ftplib::read_line(std::string *buf, ftphandle_t ctl) {
    if (buf == nullptr) throw std::invalid_argument("buf == nullptr");
    if (ctl == nullptr) throw std::invalid_argument("ctl == nullptr");

    if ((ctl->dir != FTPLIB_CONTROL) && (ctl->dir != FTPLIB_READ)) {
        return FTPLIB_E_INVALID_IO_OPERATION;
    }
    if (!buf->empty()) {
        buf->clear();
    }
    bool eof = false;
    size_t retval = 0;
    do {
        if (ctl->cavail > 0) {
            char *last = strnchr(ctl->cget, ctl->cavail, '\n');
            if (last == nullptr) {
                buf->append(ctl->cget, ctl->cavail);
                ctl->cget += ctl->cavail;
                ctl->cavail = 0;
            } else {
                int len = last - ctl->cget + 1;
                buf->append(ctl->cget, len);
                ctl->cget = last + 1;
                ctl->cavail -= len;
            }

            if (ends_with(*buf, "\r\n")) {
                buf->pop_back();
                buf->pop_back();
                *buf += "\n";
                return buf->length();  // return the line size
            } else {
                retval = buf->length();
            }
        }

        if (ctl->cput == ctl->cget) {
            ctl->cput = ctl->cget = ctl->buf;
            ctl->cavail = 0;
            ctl->cleft = FTPLIB_BUFSIZ;
        }

        if (eof) {
            return (retval == 0) ? FTPLIB_E_INVALID_IO_OPERATION : retval;
        }

        if (this->socket_wait(ctl) != FTPLIB_E_NONE) {
            return retval;
        }

        int x;
#ifndef NOSSL
        if (ctl->tlsdata) {
            x = openssl::SSL_read(ctl->ssl, ctl->cput, ctl->cleft);
        } else {
            if (ctl->tlsctrl) {
                x = openssl::SSL_read(ctl->ssl, ctl->cput, ctl->cleft);
            } else {
                x = net_read(ctl->handle, ctl->cput, ctl->cleft);
            }
        }
#else
        x = net_read(ctl->handle, ctl->cput, ctl->cleft);
#endif
        if (x == -1) {
            return FTPLIB_E_INVALID_IO_OPERATION;
        }

        if ((ctl->dir == FTPLIB_CONTROL) && (m_handle->logcb != NULL)) {
            *((ctl->cput)+x) = '\0';
            m_handle->logcb(ctl->cput, m_handle->cbarg, true);
        }

        if (x == 0) {
            eof = true;
        }
        ctl->cleft -= x;
        ctl->cavail += x;
        ctl->cput += x;
    } while (1);
    return retval;
}

ssize_t ftplib::write_line(const std::string &buf, ftphandle_t hdata) {
    if (hdata == nullptr) throw std::invalid_argument("hdata == nullptr");
    if (hdata->dir != FTPLIB_WRITE) {
        return FTPLIB_E_INVALID_IO_OPERATION;
    }
    size_t x = 0;
    int nb = 0, w;
    const char *ubp = buf.c_str();
    char lc = 0;
    char *nbp = hdata->buf;
    for (x = 0; x < buf.length(); x++) {
        if ((*ubp == '\n') && (lc != '\r')) {
            if (nb == FTPLIB_BUFSIZ) {
                if (this->socket_wait(hdata) != FTPLIB_E_NONE) {
                    return (x);
                }
#ifndef NOSSL
                if (hdata->tlsctrl) {
                    w = openssl::SSL_write(hdata->ssl, nbp, FTPLIB_BUFSIZ);
                } else {
                    w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
                }
#else
                w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
#endif
                if (w != FTPLIB_BUFSIZ) {
                    // TODO(VSF): error handling, don't write to stdout
                    // printf("write(1) returned %d, errno = %d\n", w, errno);
                    return FTPLIB_E_INVALID_IO_OPERATION;
                }
                nb = 0;
            }
            nbp[nb++] = '\r';
        }
        if (nb == FTPLIB_BUFSIZ) {
            if (this->socket_wait(hdata) != FTPLIB_E_NONE) {
                return (x);
            }

#ifndef NOSSL
            if (hdata->tlsctrl) {
                w = openssl::SSL_write(hdata->ssl, nbp, FTPLIB_BUFSIZ);
            } else {
                w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
            }
#else
            w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
#endif
            if (w != FTPLIB_BUFSIZ) {
                // printf("write(2) returned %d, errno = %d\n", w, errno);
                return FTPLIB_E_INVALID_IO_OPERATION;
            }
            nb = 0;
        }
        nbp[nb++] = lc = *ubp++;
    }

    if (nb) {
        if (socket_wait(hdata) != FTPLIB_E_NONE) {
            return (x);
        }
#ifndef NOSSL
        if (hdata->tlsctrl) {
            w = openssl::SSL_write(hdata->ssl, nbp, nb);
        } else {
            w = net_write(hdata->handle, nbp, nb);
        }
#else
        w = net_write(hdata->handle, nbp, nb);
#endif
        if (w != nb) {
            // printf("write(3) returned %d, errno = %d\n", w, errno);
            return FTPLIB_E_INVALID_IO_OPERATION;
        }
    }
    return buf.length();
}

ssize_t ftplib::write_line(const char *buf, size_t len, ftphandle_t hdata) {
    if (hdata == nullptr) throw std::invalid_argument("hdata == nullptr");
    if (hdata->dir != FTPLIB_WRITE) {
        return FTPLIB_E_INVALID_IO_OPERATION;
    }
    size_t x;
    int nb = 0, w;
    const char *ubp = buf;
    char lc = 0;
    char *nbp = hdata->buf;
    for (x = 0; x < len; x++) {
        if ((*ubp == '\n') && (lc != '\r')) {
            if (nb == FTPLIB_BUFSIZ) {
                if (this->socket_wait(hdata) != FTPLIB_E_NONE) {
                    return (x);
                }
#ifndef NOSSL
                if (hdata->tlsctrl) {
                    w = openssl::SSL_write(hdata->ssl, nbp, FTPLIB_BUFSIZ);
                } else {
                    w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
                }
#else
                w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
#endif
                if (w != FTPLIB_BUFSIZ) {
                    // TODO(VSF): error handling, don't write to stdout
                    // printf("write(1) returned %d, errno = %d\n", w, errno);
                    return FTPLIB_E_INVALID_IO_OPERATION;
                }
                nb = 0;
            }
            nbp[nb++] = '\r';
        }
        if (nb == FTPLIB_BUFSIZ) {
            if (this->socket_wait(hdata) != FTPLIB_E_NONE) {
                return (x);
            }
#ifndef NOSSL
            if (hdata->tlsctrl) {
                w = openssl::SSL_write(hdata->ssl, nbp, FTPLIB_BUFSIZ);
            } else {
                w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
            }
#else
            w = net_write(hdata->handle, nbp, FTPLIB_BUFSIZ);
#endif
            if (w != FTPLIB_BUFSIZ) {
                // printf("write(2) returned %d, errno = %d\n", w, errno);
                return FTPLIB_E_INVALID_IO_OPERATION;
            }
            nb = 0;
        }
        nbp[nb++] = lc = *ubp++;
    }

    if (nb) {
        if (socket_wait(hdata) != FTPLIB_E_NONE) {
            return (x);
        }
#ifndef NOSSL
        if (hdata->tlsctrl) {
            w = openssl::SSL_write(hdata->ssl, nbp, nb);
        } else {
            w = net_write(hdata->handle, nbp, nb);
        }
#else
        w = net_write(hdata->handle, nbp, nb);
#endif
        if (w != nb) {
            // printf("write(3) returned %d, errno = %d\n", w, errno);
            return FTPLIB_E_INVALID_IO_OPERATION;
        }
    }
    return len;
}

int ftplib::read_resp(char c, ftphandle_t hctrl) {
    if (hctrl == nullptr) throw std::invalid_argument("hctrl == nullptr");
    if (this->read_line(&hctrl->response, hctrl) == FTPLIB_E_INVALID_IO_OPERATION) {
        this->update_errormsg("Control socket read failed");
        return FTPLIB_E_ERROR;
    }

    if (hctrl->response[3] == '-') {
        std::string match = hctrl->response.substr(0, 3) + " ";
        do {
            if (this->read_line(&hctrl->response, hctrl) == FTPLIB_E_INVALID_IO_OPERATION) {
                this->update_errormsg("Control socket read failed");
                return FTPLIB_E_ERROR;
            }
        } while (hctrl->response.substr(0, 4).compare(match) == 0);
    }

    return (hctrl->response[0] == c) ? FTPLIB_E_NONE : FTPLIB_E_ERROR;
}

const std::string ftplib::last_response() noexcept {
    return ((this->m_handle) && (this->m_handle->dir == FTPLIB_CONTROL)) ? this->m_handle->response : std::string();
}

int ftplib::connect(const std::string &host) {
    int sControl;
    struct sockaddr_in sin;
    const struct hostent *phe;
    const struct servent *pse;
    int on = 1;
    int ret;

    m_handle->dir = FTPLIB_CONTROL;
    m_handle->ctrl = NULL;
    m_handle->xfered = 0;
    m_handle->xfered1 = 0;
    m_handle->tlsctrl = 0;
    m_handle->tlsdata = 0;
    m_handle->offset = 0;
    m_handle->handle = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    char *lhost = strdup(host.c_str());
    char *pnum = strnchr(lhost, ':', host.length());
    if (pnum == NULL) {
        if ((pse = getservbyname("ftp", "tcp")) == NULL) {
            this->update_errormsg("getservbyname");
            std::free(lhost);
            return FTPLIB_E_ERROR;
        }
        sin.sin_port = pse->s_port;
    } else {
        *pnum++ = '\0';
        if (isdigit(*pnum)) {
            sin.sin_port = htons(atoi(pnum));
        }  else {
            pse = getservbyname(pnum, "tcp");
            sin.sin_port = pse->s_port;
        }
    }

#if defined(_WIN32)
    if ((sin.sin_addr.s_addr = inet_addr(lhost)) == -1) {
#else
    ret = inet_aton(lhost, &sin.sin_addr);
    if (ret == 0) {
#endif
        if ((phe = gethostbyname(lhost)) == NULL) {
            this->update_errormsg("gethostbyname");
            std::free(lhost);
            return FTPLIB_E_ERROR;
        }
        memcpy(reinterpret_cast<void *>(&sin.sin_addr), phe->h_addr, phe->h_length);
    }
    std::free(lhost);

    sControl = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sControl == -1) {
        this->update_errormsg("socket");
        return FTPLIB_E_ERROR;
    }

    if (::setsockopt(sControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(&on), sizeof(on)) == -1) {
        this->update_errormsg("setsockopt");
        net_close(sControl);
        return FTPLIB_E_ERROR;
    }
    if (::connect(sControl, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin)) == -1) {
        this->update_errormsg("connect");
        net_close(sControl);
        return FTPLIB_E_ERROR;
    }

    m_handle->handle = sControl;

    if (this->read_resp('2', m_handle) == 0) {
        net_close(sControl);
        m_handle->handle = 0;
        return FTPLIB_E_ERROR;
    }

    return FTPLIB_E_NONE;
}

bool ftplib::is_connected() const noexcept {
    return (m_handle != nullptr && m_handle->handle != 0);
}

int ftplib::FtpSendCmd(const std::string &cmd, char expresp, ftphandle *hctrl) {
    if ((!hctrl->handle) || (hctrl->dir != FTPLIB_CONTROL)) {
        return FTPLIB_E_ERROR;
    }

    int x;
    std::string buf = cmd + std::string("\r\n");
#ifndef NOSSL
    if (hctrl->tlsctrl) {
        x = openssl::SSL_write(hctrl->ssl, buf.c_str(), buf.length());
    } else {
        x = net_write(hctrl->handle, buf.c_str(), buf.length());
    }
#else
    x = net_write(hctrl->handle, buf.c_str(), buf.length());
#endif
    if (x <= 0) {
        this->update_errormsg("write");
        return FTPLIB_E_ERROR;
    }

    if (m_handle->logcb != nullptr) {
        m_handle->logcb(buf.c_str(), m_handle->cbarg, false);
    }
    return this->read_resp(expresp, hctrl);
}

int ftplib::login(const std::string &user, const std::string &pass) {
    if (this->FtpSendCmd("USER " + user, '3', this->m_handle) != FTPLIB_E_NONE) {
        if (this->m_handle->ctrl != NULL || this->last_response()[0] == '2') {
            return FTPLIB_E_NONE;
        }
        return FTPLIB_E_ERROR;
    }
    return this->FtpSendCmd("PASS " + pass, '2', this->m_handle);
}

int ftplib::FtpAcceptConnection(ftphandle *hdata, ftphandle *hctrl) {
    fd_set mask;
    FD_ZERO(&mask);
    FD_SET(hctrl->handle, &mask);
    FD_SET(hdata->handle, &mask);
    struct timeval tv = {
        .tv_sec = ACCEPT_TIMEOUT,
        .tv_usec = 0
    };
    int fd = (hctrl->handle < hdata->handle) ? hctrl->handle : hdata->handle;
    int i = select(fd + 1, &mask, NULL, NULL, &tv);
    if (i == -1) {
        hctrl->response = strerror(errno);
        this->update_errormsg("select");
        net_close(hdata->handle);
        hdata->handle = 0;
        return FTPLIB_E_ERROR;
    } else if (i == 0) {
        hctrl->response = "timed out waiting for connection";
        hctrl->errormsg = "timed out waiting for connection";
        net_close(hdata->handle);
        hdata->handle = 0;
        return FTPLIB_E_ERROR;
    } else {
        if (FD_ISSET(hdata->handle, &mask)) {
            struct sockaddr addr;
            socklen_t addrlen = sizeof(addr);
            int sdata = accept(hdata->handle, &addr, &addrlen);
            auto serrno = errno;
            net_close(hdata->handle);
            if (sdata > 0) {
                hdata->handle = sdata;
                hdata->ctrl = hctrl;
                return FTPLIB_E_NONE;
            } else {
                hctrl->response = strerror(serrno);
                hdata->handle = 0;
                return FTPLIB_E_ERROR;
            }
        } else if (FD_ISSET(hctrl->handle, &mask)) {
            net_close(hdata->handle);
            hdata->handle = 0;
            this->read_resp('2', hctrl);
            return FTPLIB_E_ERROR;
        }
    }
    return FTPLIB_E_ERROR;
}

int ftplib::FtpAccess(const std::string &path, accesstype type, transfermode mode, ftphandle_t hctl,
    ftphandle_t *hdata) {
    int dir;

    if ((path.empty() || (hctl == nullptr)) &&
        ((type == accesstype_filewrite) || (type == accesstype_fileread) ||
         (type == accesstype_filereadappend) || (type == accesstype_filewriteappend))) {
        hctl->response = "Missing path argument for file transfer";
        hctl->errormsg = "Missing path argument for file transfer";
        return FTPLIB_E_ERROR;
    }

    std::string cmd = "TYPE ";
    cmd += mode;
    if (this->FtpSendCmd(cmd, '2', hctl) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }

    switch (type) {
        case accesstype_dir:
            cmd = "NLST";
            dir = FTPLIB_READ;
            break;
        case accesstype_dirverbose:
            cmd = "LIST -aL";
            dir = FTPLIB_READ;
            break;
        case accesstype_filereadappend:
        case accesstype_fileread:
            cmd = "RETR";
            dir = FTPLIB_READ;
            break;
        case accesstype_filewriteappend:
        case accesstype_filewrite:
            cmd = "STOR";
            dir = FTPLIB_WRITE;
            break;
        default:
            hctl->response = "Invalid open type " + std::to_string(type) + "\n";
            return FTPLIB_E_ERROR;
        }

        if (!path.empty()) {
            cmd += " " + path;
        }

        if (hctl->cmode == connmode_pasv) {
            if (FtpOpenPasv(hctl, hdata, mode, dir, cmd) == -1) {
                return FTPLIB_E_ERROR;
            }
        }

        if (hctl->cmode == connmode_port) {
            if (FtpOpenPort(hctl, hdata, mode, dir, cmd) == -1) return FTPLIB_E_ERROR;
            if (FtpAcceptConnection(*hdata, hctl) != FTPLIB_E_NONE) {
                this->FtpClose(*hdata);
                *hdata = nullptr;
                return FTPLIB_E_ERROR;
            }
    }

#ifndef NOSSL
    if (hctl->tlsdata) {
        (*hdata)->ssl = openssl::SSL_new(hctl->ctx);
        (*hdata)->sbio = openssl::BIO_new_socket((*hdata)->handle, BIO_NOCLOSE);
        openssl::SSL_set_bio((*hdata)->ssl, (*hdata)->sbio, (*hdata)->sbio);
        auto ret = openssl::SSL_connect((*hdata)->ssl);
        if (ret != 1) {
            return 0;
        }
        (*hdata)->tlsdata = 1;
    }
#endif
    return FTPLIB_E_NONE;
}

int ftplib::FtpOpenPort(ftphandle_t hctrl, ftphandle_t *hdata, transfermode mode, int dir, const std::string &cmd) {
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
    } sin;
    struct linger lng = { 0, 0 };
    int on = 1;
    ftphandle *ctrl;

    if (hctrl->dir != FTPLIB_CONTROL) {
        return (-1);
    }

    if ((dir != FTPLIB_READ) && (dir != FTPLIB_WRITE)) {
        hctrl->response = "Invalid direction " + std::to_string(dir) + "\n";
        return (-1);
    }

    if ((mode != transfermode_ascii) && (mode != transfermode_image)) {
        hctrl->response = "Invalid mode ";
        hctrl->response += mode;
        hctrl->response += "\n";
        return (-1);
    }

    socklen_t l = sizeof(sin);
    if (getsockname(hctrl->handle, &sin.sa, &l) < 0) {
        perror("getsockname");
        return (-1);
    }

    auto sdata = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sdata == -1) {
        perror("socket");
        return -1;
    }

    if (setsockopt(sdata, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(&on), sizeof(on)) == -1) {
        perror("setsockopt");
        net_close(sdata);
        return (-1);
    }

    if (setsockopt(sdata, SOL_SOCKET,SO_LINGER, SETSOCKOPT_OPTVAL_TYPE(&lng), sizeof(lng)) == -1) {
        perror("setsockopt");
        net_close(sdata);
        return (-1);
    }

    sin.in.sin_port = 0;
    if (bind(sdata, &sin.sa, sizeof(sin)) == -1) {
        perror("bind");
        net_close(sdata);
        return (-1);
    }

    if (listen(sdata, 1) < 0) {
        perror("listen");
        net_close(sdata);
        return (-1);
    }

    if (getsockname(sdata, &sin.sa, &l) < 0) {
        return 0;
    }
    char buf[256];
    sprintf(buf, "PORT %hhu,%hhu,%hhu,%hhu,%hhu,%hhu",
        (unsigned char) sin.sa.sa_data[2],
        (unsigned char) sin.sa.sa_data[3],
        (unsigned char) sin.sa.sa_data[4],
        (unsigned char) sin.sa.sa_data[5],
        (unsigned char) sin.sa.sa_data[0],
        (unsigned char) sin.sa.sa_data[1]);
    if (!FtpSendCmd(buf, '2', hctrl)) {
        net_close(sdata);
        return -1;
    }

    if (m_handle->offset != 0) {
            std::string s = sprint_rest(m_handle->offset);
            if (!FtpSendCmd(s, '3', hctrl)) {
                net_close(sdata);
                return 0;
            }
        }

    if ((ctrl = static_cast<ftphandle *>(std::calloc(1, sizeof(ftphandle)))) == nullptr) {
        perror("calloc");
        net_close(sdata);
        return (-1);
    }

    if ((mode == 'A') && ((ctrl->buf = static_cast<char*>(std::malloc(FTPLIB_BUFSIZ))) == nullptr)) {
        perror("calloc");
        net_close(sdata);
        std::free(ctrl);
        return -1;
    }

    if (!FtpSendCmd(cmd, '1', hctrl)) {
        FtpClose(*hdata);
        *hdata = nullptr;
        return (-1);
    }

    ctrl->handle = sdata;
    ctrl->dir = dir;
    ctrl->ctrl = (hctrl->cmode == connmode_pasv) ? hctrl : nullptr;
    ctrl->idletime = hctrl->idletime;
    ctrl->cbarg = hctrl->cbarg;
    ctrl->xfered = 0;
    ctrl->xfered1 = 0;
    ctrl->cbbytes = hctrl->cbbytes;
    if (ctrl->idletime.tv_sec || ctrl->idletime.tv_usec) {
        ctrl->idlecb = hctrl->idlecb;
    } else {
        ctrl->idlecb = nullptr;
    }

    if (ctrl->cbbytes) {
        ctrl->xfercb = hctrl->xfercb;
    } else {
        ctrl->xfercb = nullptr;
    }

    *hdata = ctrl;

    return FTPLIB_E_NONE;
}

int ftplib::FtpOpenPasv(ftphandle_t hctrl, ftphandle_t *hdata, transfermode mode, int dir, const std::string &cmd) {
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
    } sin;
    struct linger lng = { 0, 0 };
    unsigned int l;
    ftphandle *ctrl;
    unsigned char v[6];
    int ret;

    if (hctrl->dir != FTPLIB_CONTROL) {
        return (-1);
    }

    if ((dir != FTPLIB_READ) && (dir != FTPLIB_WRITE)) {
        hctrl->response = "Invalid direction " + std::to_string(dir) + "\n";
        return (-1);
    }
    if ((mode != transfermode_ascii) && (mode != transfermode_image)) {
        hctrl->response = "Invalid mode ";
        hctrl->response += std::to_string(mode);
        hctrl->response = "\n";
        return (-1);
    }
    l = sizeof(sin);

    memset(&sin, 0, l);
    sin.in.sin_family = AF_INET;
    if (!FtpSendCmd("PASV", '2', hctrl)) return (-1);
    size_t pos = hctrl->response.find_first_of('(');
    if (pos == std::string::npos) return -1;
    const char *cp = &hctrl->response[pos + 1];
#if defined(_WIN32)
    unsigned int v_i[6];
        sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
        for (int i = 0; i < 6; i++) v[i] = (unsigned char) v_i[i];
#else
    sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif
    if (hctrl->correctpasv) {
        if (this->correct_pasv_response(v) != FTPLIB_E_NONE) {
            return FTPLIB_E_INVALID_IO_OPERATION;
        }
    }
    sin.sa.sa_data[2] = v[2];
    sin.sa.sa_data[3] = v[3];
    sin.sa.sa_data[4] = v[4];
    sin.sa.sa_data[5] = v[5];
    sin.sa.sa_data[0] = v[0];
    sin.sa.sa_data[1] = v[1];
    if (m_handle->offset != 0) {
        std::string lcmd = this->sprint_rest(m_handle->offset);
        if (FtpSendCmd(lcmd, '3', hctrl) != FTPLIB_E_NONE) {
            return FTPLIB_E_ERROR;
        }
    }

    auto sdata = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sdata == -1) {
        perror("socket");
        return (-1);
    }

    int on = 1;
    if (setsockopt(sdata, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(&on), sizeof(on)) == -1) {
        perror("setsockopt");
        net_close(sdata);
        return (-1);
    }

    if (setsockopt(sdata, SOL_SOCKET, SO_LINGER, SETSOCKOPT_OPTVAL_TYPE(&lng), sizeof(lng)) == -1) {
        perror("setsockopt");
        net_close(sdata);
        return (-1);
    }

    if (hctrl->dir != FTPLIB_CONTROL) {
        return (-1);
    }

    std::string lcmd = cmd + "\r\n\0";
#ifndef NOSSL
    if (hctrl->tlsctrl) {
        ret = openssl::SSL_write(hctrl->ssl, lcmd.c_str(), lcmd.length());
    } else {
        ret = net_write(hctrl->handle, lcmd.c_str(), lcmd.length());
    }
#else
    ret = net_write(hctrl->handle, lcmd.c_str(), lcmd.length());
#endif
    if (ret <= 0) {
        ::perror("write");
        hctrl->errormsg = std::string("write:") + strerror(errno);
        return (-1);
    }

    if (::connect(sdata, &sin.sa, sizeof(sin.sa)) == -1) {
        hctrl->response = std::string("connect:") + strerror(errno);
        hctrl->errormsg = std::string("connect:") + strerror(errno);
        net_close(sdata);
        return (-1);
    }

    if (!this->read_resp('1', hctrl)) {
        net_close(sdata);
        return (-1);
    }

    if ((ctrl = static_cast<ftphandle*>(std::calloc(1, sizeof(ftphandle)))) == nullptr) {
        perror("calloc");
        net_close(sdata);
        return (-1);
    }

    if ((mode == 'A') && ((ctrl->buf = static_cast<char*>(std::malloc(FTPLIB_BUFSIZ))) == nullptr)) {
        perror("calloc");
        net_close(sdata);
        std::free(ctrl);
        return (-1);
    }

    ctrl->handle = sdata;
    ctrl->dir = dir;
    ctrl->ctrl = (hctrl->cmode == connmode_pasv) ? hctrl : nullptr;
    ctrl->idletime = hctrl->idletime;
    ctrl->cbarg = hctrl->cbarg;
    ctrl->xfered = 0;
    ctrl->xfered1 = 0;
    ctrl->cbbytes = hctrl->cbbytes;
    if (ctrl->idletime.tv_sec || ctrl->idletime.tv_usec) {
        ctrl->idlecb = hctrl->idlecb;
    } else {
        ctrl->idlecb = nullptr;
    }
    if (ctrl->cbbytes) {
        ctrl->xfercb = hctrl->xfercb;
    } else {
        ctrl->xfercb = nullptr;
    }
    *hdata = ctrl;

    return FTPLIB_E_NONE;
}

int ftplib::FtpClose(ftphandle_t hdata) {
    ftphandle_t ctrl;

    if (hdata->dir == FTPLIB_WRITE) {
        if (hdata->buf != nullptr) {
            this->write_line("", hdata);
        }
    } else if (hdata->dir != FTPLIB_READ) {
        return 0;
    }

    if (hdata->buf != nullptr) {
        std::free(hdata->buf);
        hdata->buf = nullptr;
    }
    ::shutdown(hdata->handle, 2);
    net_close(hdata->handle);

    ctrl = hdata->ctrl;
#ifndef NOSSL
    if (hdata->ssl != nullptr) {
        openssl::SSL_free(hdata->ssl);
        hdata->ssl = nullptr;
    }
#endif
    std::free(hdata);
    if (ctrl != nullptr) {
        return this->read_resp('2', ctrl);
    }
    return FTPLIB_E_NONE;
}

std::size_t ftplib::FtpRead(void *buf, size_t max, ftphandle_t hdata) {
    if (buf == nullptr || max == 0 || hdata == nullptr || hdata->dir != FTPLIB_READ) {
        return (0);
    }

    int i = -1;
    if (hdata->buf != nullptr) {
        std::string lbuf;
        i = this->read_line(&lbuf, hdata);
        memcpy(buf, lbuf.c_str(), (max < lbuf.length() + 1) ? max : (lbuf.length() + 1));
    } else {
        if ((i = this->socket_wait(hdata)) != FTPLIB_E_NONE) {
            return (0);
        }
    #ifndef NOSSL
        if (hdata->tlsdata) {
            i = openssl::SSL_read(hdata->ssl, buf, max);
        } else {
            i = net_read(hdata->handle, buf, max);
        }
    #else
        i = net_read(hdata->handle, buf, max);
    #endif
    }
    if (i == -1) {
        return (0);
    }

    hdata->xfered += i;
    if (hdata->xfercb && hdata->cbbytes) {
        hdata->xfered1 += i;
        if (hdata->xfered1 > hdata->cbbytes) {
            if (hdata->xfercb(hdata->xfered, hdata->cbarg) == 0) {
                return (0);
            }
            hdata->xfered1 = 0;
        }
    }
    return i;
}

std::size_t ftplib::FtpRead(std::string *str, ftphandle_t hdata) {
    if (str == nullptr) throw std::invalid_argument("str");
    if (hdata == nullptr) throw std::invalid_argument("str");

    if (hdata->dir != FTPLIB_READ) {
        return FTPLIB_E_ERROR;
    }

    char *buf = nullptr;
    int max = 1024;
    int i = -1;
    if (hdata->buf != nullptr) {
        i = this->read_line(str, hdata);
    } else {
        if ((i = this->socket_wait(hdata)) != FTPLIB_E_NONE) {
            return FTPLIB_E_ERROR;
        }
        str->reserve(max+1);
        buf = &(*str)[0];
    #ifndef NOSSL
        if (hdata->tlsdata) {
            i = openssl::SSL_read(hdata->ssl, buf, max);
        } else {
            i = net_read(hdata->handle, buf, max);
        }
    #else
        i = net_read(hdata->handle, buf, max);
    #endif
    }
    if (i == -1) {
        return FTPLIB_E_ERROR;
    }

    hdata->xfered += i;
    if (hdata->xfercb && hdata->cbbytes) {
        hdata->xfered1 += i;
        if (hdata->xfered1 > hdata->cbbytes) {
            if (hdata->xfercb(hdata->xfered, hdata->cbarg) == 0) {
                return FTPLIB_E_ERROR;
            }
            hdata->xfered1 = 0;
        }
    }
    return i;  // return size
}

size_t ftplib::FtpWrite(const std::string &buf, ftphandle_t hdata) {
    return this->FtpWrite(buf.c_str(), buf.length() + 1, hdata);
}
 
size_t ftplib::FtpWrite(const void *buf, size_t len, ftphandle_t hdata) {
    int i;

    if (hdata == nullptr || hdata->dir != FTPLIB_WRITE) {
        return 0;
    }

    if (hdata->buf != nullptr) {
        i = this->write_line(static_cast<const char*>(buf), hdata);
    } else {
        this->socket_wait(hdata);
#ifndef NOSSL
        if (hdata->tlsdata) {
            i = openssl::SSL_write(hdata->ssl, buf, len);
        } else {
            i = net_write(hdata->handle, buf, len);
        }
#else
        i = net_write(hdata->handle, buf, len);
#endif
    }

    if (i == -1) {
        return 0;
    }
    hdata->xfered += i;

    if (hdata->xfercb && hdata->cbbytes) {
        hdata->xfered1 += i;
        if (hdata->xfered1 > hdata->cbbytes) {
            if (hdata->xfercb(hdata->xfered, hdata->cbarg) == 0) {
                return 0;
            }
            hdata->xfered1 = 0;
        }
    }
    return i;
}

int ftplib::site(const std::string &cmd) {
    return (this->FtpSendCmd("SITE " + cmd, '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::raw(const std::string &cmd) {
    return (this->FtpSendCmd(cmd, '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::systype(std::string *buf) {
    if (this->FtpSendCmd("SYST", '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    } else {
        std::string s = &m_handle->response[4];
        std::size_t pos = s.find_first_of(" ");
        if (pos == std::string::npos) {
            *buf = s;
        } else {
            *buf = s.substr(0, pos - 1);
        }
    }
    return FTPLIB_E_NONE;
}

int ftplib::mkdir(const std::string &path) {
    if (path.empty()) return FTPLIB_E_ERROR;
    return (this->FtpSendCmd("MKD " + path, '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::chdir(const std::string &path) {
    return (this->FtpSendCmd("CWD " + path, '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::cdup() {
    return (this->FtpSendCmd("CDUP", '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::rmdir(const std::string &path) {
    return (this->FtpSendCmd("RMD " + path, '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::pwd(std::string *path) {
    if (path == nullptr) {
        return FTPLIB_E_ERROR;
    }

    if (this->FtpSendCmd("PWD", '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }
    size_t pos;
    std::string s = m_handle->response;
    if ((pos = s.find_first_of('"')) == std::string::npos) {
        return FTPLIB_E_ERROR;
    }
    s = s.substr(pos + 1);
    if ((pos = s.find_first_of('"')) == std::string::npos) {
        *path = s;
    } else {
        *path = s.substr(0, pos - 1);
    }
    return FTPLIB_E_NONE;
}

int ftplib::FtpXfer(void *buffer, size_t size, const std::string &path, ftphandle_t hctrl, accesstype type,
                    transfermode mode) {
    char *dbuf;
    size_t size_remaining;
    ftphandle_t hdata;

    if (buffer == NULL || size == 0) {
        return 0;
    }

    if (type == accesstype_filewriteappend) {
        if (m_handle->offset < 0) return 0;
        size_t offset = m_handle->offset;
        dbuf = static_cast<char *>(buffer) + offset;
        size_remaining = size < offset ? 0 : size - offset;
    } else {
        dbuf = static_cast<char *>(buffer);
        size_remaining = size;
    }

    if (this->FtpAccess(path, type, mode, hctrl, &hdata) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }

    if ((type == accesstype_filewrite) || (type == accesstype_filewriteappend)) {
        int l = FTPLIB_BUFSIZ < size_remaining ? FTPLIB_BUFSIZ : size_remaining;
        while (l > 0) {
        int c;
        if ((c = this->FtpWrite(dbuf, l, hdata)) < l) {
            printf("short write: passed %d, wrote %d\n", l, c);
            break;
        }
        dbuf += c;
        size_remaining -= c;
        l = FTPLIB_BUFSIZ < size_remaining ? FTPLIB_BUFSIZ : size_remaining;
        }
    } else {
        int c;
        int l = FTPLIB_BUFSIZ < size_remaining ? FTPLIB_BUFSIZ : size_remaining;
        while ((c = this->FtpRead(dbuf, l, hdata)) > 0) {
            if (c > l) c = l; // avoid overflow
            dbuf += c;
            size_remaining -= c;
            l = FTPLIB_BUFSIZ < size_remaining ? FTPLIB_BUFSIZ : size_remaining;
        }
        size_remaining  = size_remaining;
    }
    return this->FtpClose(hdata);
}

int ftplib::FtpXfer(const std::filesystem::path &localfile, const std::string &path, ftphandle_t hctrl,
            accesstype type, transfermode mode) {
    char *dbuf = nullptr;
    FILE *local = nullptr;
    ftphandle_t hdata = nullptr;

    if (localfile.empty() == false) {
        char ac[3] = "  ";
        if ((type == accesstype_dir) || (type == accesstype_dirverbose)) { ac[0] = 'w'; ac[1] = '\0'; }
        if (type == accesstype_fileread) { ac[0] = 'w'; ac[1] = '\0'; }
        if (type == accesstype_filewriteappend) { ac[0] = 'r'; ac[1] = '\0'; }
        if (type == accesstype_filereadappend) { ac[0] = 'a'; ac[1] = '\0'; }
        if (type == accesstype_filewrite) { ac[0] = 'r'; ac[1] = '\0'; }
        if (mode == transfermode_image) ac[1] = 'b';

        if ((local = fopen64(localfile.c_str(), ac)) == NULL) {
            hctrl->response = strerror(errno);
            return 0;
        }
        if (type == accesstype_filewriteappend) {
            fseeko64(local, m_handle->offset, SEEK_SET);
        }
    }
    if (local == nullptr) {
        local = ((type == accesstype_filewrite) || (type == accesstype_filewriteappend)) ? stdin : stdout;
    }
    if (this->FtpAccess(path, type, mode, hctrl, &hdata) != FTPLIB_E_NONE) {
        if (local != nullptr) {
            fclose(local);
            local = nullptr;
        }
        return FTPLIB_E_ERROR;
    }

    dbuf = static_cast<char*>(std::malloc(FTPLIB_BUFSIZ));
    if ((type == accesstype_filewrite) || (type == accesstype_filewriteappend)) {
        size_t l;
        while ((l = std::fread(dbuf, 1, FTPLIB_BUFSIZ, local)) > 0) {
            size_t c;
            if ((c = this->FtpWrite(dbuf, l, hdata)) < l) {
                printf("short write: passed %ld, wrote %ld\n", l, c);
                break;
            }
        }
    } else {
        size_t l;
        while ((l = this->FtpRead(dbuf, FTPLIB_BUFSIZ, hdata)) > 0) {
            if (std::fwrite(dbuf, 1, l, local) == 0) {
                this->update_errormsg("localfile write");
                break;
            }
        }
    }

    if (dbuf != nullptr) {
        std::free(dbuf);
        dbuf = nullptr;
    }
    if (local != nullptr) {
        fflush(local);
        fclose(local);
        local = nullptr;
    }
    return this->FtpClose(hdata);
}

int ftplib::FtpXfer(std::string *str, const std::string &path, ftphandle_t hctrl, accesstype type,
                    transfermode mode) {
    ftphandle_t hdata;

    if (str == nullptr) {
        return 0;
    }

    if ((type == accesstype_filewriteappend) || (type == accesstype_filereadappend)) {
    } else {
        *str = "";
    }

    if (!this->FtpAccess(path, type, mode, hctrl, &hdata)) {
        return 0;
    }

    if ((type == accesstype_filewrite) || (type == accesstype_filewriteappend)) {
        this->FtpWrite(*str, hdata);
    } else {
        while (1) {
            std::string s;
            auto c = this->FtpRead(&s, hdata);
            if (c == 0) {
                break;
            }
            *str += s;
        }
    }
    return this->FtpClose(hdata);
}

int ftplib::nlst(const std::filesystem::path &outputfile, const std::string &path) {
    m_handle->offset = 0;
    return this->FtpXfer(outputfile, path, m_handle, accesstype_dir, transfermode_ascii);
}

int ftplib::nlst(void *buffer, std::size_t size, const std::string &path) {
    m_handle->offset = 0;
    return this->FtpXfer(buffer, size, path, m_handle, accesstype_dir, transfermode_ascii);
}

int ftplib::nlst(std::string *str, const std::string &path) {
    m_handle->offset = 0;
    return this->FtpXfer(str, path, m_handle, accesstype_dir, transfermode_ascii);
}

/*
 * FtpDir - issue a LIST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::dir(const std::filesystem::path &outputfile, const std::string &path) {
    m_handle->offset = 0;
    return this->FtpXfer(outputfile, path, m_handle, accesstype_dirverbose, transfermode_ascii);
}

/*
 * FtpDir - issue a LIST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::dir(void *buffer, std::size_t size, const std::string &path) {
    m_handle->offset = 0;
    return this->FtpXfer(buffer, size, path, m_handle, accesstype_dirverbose, transfermode_ascii);
}

int ftplib::size(const std::string &path, int *size, transfermode mode) {
    std::string cmd = std::string("TYPE ");
    cmd += mode;

    if (this->FtpSendCmd(cmd, '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }

    cmd = std::string("SIZE ") + path;
    if (this->FtpSendCmd(cmd, '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }

    int resp, sz;
    if (sscanf(m_handle->response.c_str(), "%d %d", &resp, &sz) != 2) {
        return FTPLIB_E_ERROR;
    }

    *size = sz;
    return FTPLIB_E_NONE;
}

int ftplib::moddate(const std::string &path, std::string *dt) {
    if (path.empty() || dt == nullptr) {
        return FTPLIB_E_ERROR;
    }
    if (this->FtpSendCmd("MDTM " + path, '2', this->m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }
    *dt = this->m_handle->response.substr(4);
    return FTPLIB_E_NONE;
}

int ftplib::get(const std::filesystem::path &outputfile, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(outputfile, path, m_handle,
        ((offset == 0) ? accesstype_fileread : accesstype_filereadappend), mode);
}

int ftplib::get(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(buffer, size , path, m_handle,
        ((offset == 0) ? accesstype_fileread : accesstype_filereadappend), mode);
}

int ftplib::put(const std::filesystem::path &inputfile, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(inputfile, path, m_handle,
        ((offset == 0) ? accesstype_filewrite : accesstype_filewriteappend), mode);
}

int ftplib::put(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(buffer, size, path, m_handle,
        ((offset == 0) ? accesstype_filewrite : accesstype_filewriteappend), mode);
}

int ftplib::rename(const std::string &src, const std::string &dst) {
    if (this->FtpSendCmd("RNFR " + src, '3', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    } else if (this->FtpSendCmd("RNTO " + dst, '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }
    return FTPLIB_E_NONE;
}

int ftplib::del(const std::string &path) {
    return (this->FtpSendCmd("DELE " + path, '2', m_handle) != FTPLIB_E_NONE) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
}

int ftplib::quit() {
    if (this->m_handle == nullptr || this->m_handle->dir != FTPLIB_CONTROL) {
        return FTPLIB_E_ERROR;
    }

    if (m_handle->handle == 0) {
        if(!m_handle->response.empty()) {
            m_handle->response.clear();
        }
        m_handle->response = "error: no anwser from server";
        return FTPLIB_E_NO_ANSWER;
    }

    int retval = FTPLIB_E_NONE;
    if (this->FtpSendCmd("QUIT", '2', m_handle) != FTPLIB_E_NONE) {
        retval = FTPLIB_E_ERROR;
    }

    net_close(m_handle->handle);
    m_handle->handle = 0;
    return retval;
}
 
int ftplib::Fxp(ftplib *src, ftplib *dst, const std::string &pathSrc, const std::string &pathDst, transfermode mode,
                fxpmethod method) {
    unsigned char v[6];
    int retval = 0;

    std::string cmd = "TYPE ";
    cmd += mode;
    if (dst->FtpSendCmd(cmd, '2', dst->m_handle) != FTPLIB_E_NONE) {
        return -1;
    }

    if (src->FtpSendCmd(cmd, '2', src->m_handle) != FTPLIB_E_NONE) {
        return -1;
    }

    if (method == fxpmethod_defaultfxp) {
        // PASV dst
        if (dst->FtpSendCmd("PASV", '2', dst->m_handle) != FTPLIB_E_NONE) {
            return -1;
        }

        size_t pos = dst->m_handle->response.find('(');
        if (pos == std::string::npos) {
            return -1;
        }

        const char *cp = &dst->m_handle->response[pos + 1];
#if defined(_WIN32)
        unsigned int v_i[6];
        sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
        for (int i = 0; i < 6; i++) {
            v[i] = (unsigned char) v_i[i];
        }
#else
        sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif
        if (dst->m_handle->correctpasv) {
            if (dst->correct_pasv_response(v) != FTPLIB_E_NONE) {
                return FTPLIB_E_INVALID_IO_OPERATION;
            }
        }

        // PORT src

        // sprintf(buf, "PORT %d,%d,%d,%d,%d,%d", v[2], v[3], v[4], v[5], v[0], v[1]);
        cmd = "PORT " + std::to_string(v[2]) + "," + std::to_string(v[3]) + "," + std::to_string(v[4]) + "," +
            std::to_string(v[5]) + "," + std::to_string(v[0]) + "," + std::to_string(v[1]);
        if (src->FtpSendCmd(cmd, '2', src->m_handle) != FTPLIB_E_NONE) {
            return -1;
        }

        // RETR src
        cmd = "RETR";
        if (!pathSrc.empty()) {
            cmd += " " + pathSrc;
        }

        if (src->FtpSendCmd(cmd, '1', src->m_handle) != FTPLIB_E_NONE) {
            return FTPLIB_E_ERROR;
        }

        // STOR dst
        cmd = "STOR";
        if (!pathDst.empty()) {
                cmd += " " + pathDst;
        }

        if (dst->FtpSendCmd(cmd, '1', dst->m_handle) != FTPLIB_E_NONE) {
            /// this closes the data connection, to abort the RETR on the source ftp. all hail pftp, it took me several
            /// hours and i was absolutely clueless, playing around with ABOR and whatever, when i desperately checked
            /// the pftp source which gave me this final hint. thanks dude(s).
            dst->FtpSendCmd("PASV", '2', dst->m_handle);
            src->read_resp('4', src->m_handle);
            return FTPLIB_E_ERROR;
        }
        retval = (src->read_resp('2', src->m_handle)) & (dst->read_resp('2', dst->m_handle));
    } else {
        // PASV src
        if (src->FtpSendCmd("PASV", '2', src->m_handle) != FTPLIB_E_NONE) {
            return -1;
        }

        size_t pos = src->m_handle->response.find('(');
        if (pos == std::string::npos) {
            return -1;
        }

        const char *cp = &dst->m_handle->response[pos + 1];
#if defined(_WIN32)
        unsigned int v_i[6];
        sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
        for (int i = 0; i < 6; i++) v[i] = (unsigned char) v_i[i];
#else
        sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif
        if (src->m_handle->correctpasv) {
            if (src->correct_pasv_response(v) != FTPLIB_E_NONE) {
                return -1;
            }
        }

        // PORT dst
        cmd = "PORT " + std::to_string(v[2]) + "," + std::to_string(v[3]) + "," + std::to_string(v[4]) + "," +
            std::to_string(v[5]) + "," + std::to_string(v[0]) + "," + std::to_string(v[1]);
        if (dst->FtpSendCmd(cmd, '2', dst->m_handle) != FTPLIB_E_NONE) {
            return -1;
        }

        // STOR dest
        cmd = "STOR";
        if (!pathDst.empty()) {
            cmd += " " + pathDst;
        }
        if (dst->FtpSendCmd(cmd, '1', dst->m_handle) != FTPLIB_E_NONE) {
            return FTPLIB_E_ERROR;
        }

        // RETR src
        cmd = "RETR";
        if (!pathSrc.empty()) {
            cmd += " " + pathSrc;
        }
        if (src->FtpSendCmd(cmd, '1', src->m_handle) != FTPLIB_E_NONE) {
            src->FtpSendCmd("PASV", '2', src->m_handle);
            dst->read_resp('4', dst->m_handle);
            return FTPLIB_E_ERROR;
        }

        // wait til its finished!
        retval = (src->read_resp('2', src->m_handle)) & (dst->read_resp('2', dst->m_handle));
    }

    return retval;
}

int ftplib::SetDataEncryption(dataencryption enc) {
#ifdef NOSSL
    (void)enc;
    return FTPLIB_E_SSL_NOT_SUPPORTED;
#else
    if (m_handle->tlsctrl == 0) {
        return FTPLIB_E_ERROR;
    }
    if (this->FtpSendCmd("PBSZ 0", '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }
    switch (enc) {
        case dataencryption_unencrypted: {
            m_handle->tlsdata = 0;
            if (FtpSendCmd("PROT C", '2', m_handle) != FTPLIB_E_NONE) {
                return FTPLIB_E_ERROR;
            }
            break;
        }
        case dataencryption_secure: {
            m_handle->tlsdata = 1;
            if (FtpSendCmd("PROT P", '2', m_handle) != FTPLIB_E_NONE) {
                return FTPLIB_E_ERROR;
            }
            break;
        }
        default: {
            return FTPLIB_E_ERROR;
        }
    }
    return FTPLIB_E_NONE;
#endif
}

int ftplib::NegotiateEncryption() {
#ifdef NOSSL
    return FTPLIB_E_SSL_NOT_SUPPORTED;
#else
    if (FtpSendCmd("AUTH TLS", '2', m_handle) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }

    m_handle->sbio = openssl::BIO_new_socket(m_handle->handle, BIO_NOCLOSE);
    openssl::SSL_set_bio(m_handle->ssl, m_handle->sbio, m_handle->sbio);

    int ret = openssl::SSL_connect(m_handle->ssl);
    if (ret == 1) {
        m_handle->tlsctrl = 1;
    }

    if (m_handle->certcb != nullptr) {
        X509 *cert = openssl::SSL_get_peer_certificate(m_handle->ssl);
        if (m_handle->certcb(m_handle->cbarg, cert) == false) {
            return FTPLIB_E_ERROR;
        }
    }
    return (ret < 1) ? FTPLIB_E_ERROR : FTPLIB_E_NONE;
#endif
}

void ftplib::SetCallbackCertFunction(FtpCallbackCert pointer) {
#ifdef NOSSL
    (void)pointer;
#else
    m_handle->certcb = pointer;
#endif
}

void ftplib::SetCallbackIdleFunction(FtpCallbackIdle pointer) {
    m_handle->idlecb = pointer;
}

void ftplib::SetCallbackXferFunction(FtpCallbackXfer pointer) {
    m_handle->xfercb = pointer;
}

void ftplib::SetCallbackLogFunction(FtpCallbackLog pointer) {
    m_handle->logcb = pointer;
}

void ftplib::SetCallbackArg(void *arg) {
    m_handle->cbarg = arg;
}

void ftplib::SetCallbackBytes(off64_t bytes) {
    m_handle->cbbytes = bytes;
}

void ftplib::SetCorrectPasv() {
    m_handle->correctpasv = true;
}

void ftplib::UnsetCorrectPasv() {
    m_handle->correctpasv = false;
}

void ftplib::SetCallbackIdletime(int time) {
    m_handle->idletime.tv_sec = time / 1000;
    m_handle->idletime.tv_usec = (time % 1000) * 1000;
}

void ftplib::SetConnmode(connmode mode) {
    m_handle->cmode = mode;
}

void ftplib::clear_handle(ftphandle_t handle) {
    if (handle == nullptr) {
        throw std::invalid_argument("handle is null");
    }
    handle->dir = FTPLIB_CONTROL;
    handle->ctrl = nullptr;
    handle->cmode = connmode_pasv;
    handle->idlecb = nullptr;
    handle->idletime.tv_sec = handle->idletime.tv_usec = 0;
    handle->cbarg = nullptr;
    handle->xfered = 0;
    handle->xfered1 = 0;
    handle->cbbytes = 0;
    handle->tlsctrl = 0;
    handle->tlsdata = 0;
    handle->certcb = nullptr;
    handle->offset = 0;
    handle->handle = 0;
    handle->logcb = nullptr;
    handle->xfercb = nullptr;
    handle->correctpasv = false;
}

int ftplib::correct_pasv_response(unsigned char *v) {
    struct sockaddr ipholder;
    socklen_t ipholder_size = sizeof(ipholder);

    if (getpeername(m_handle->handle, &ipholder, &ipholder_size) == -1) {
        perror("getpeername");
        net_close(m_handle->handle);
        return FTPLIB_E_ERROR;
    }

    for (int i = 2; i < 6; i++) v[i] = ipholder.sa_data[i];

    return FTPLIB_E_NONE;
}

ftphandle_t ftplib::RawOpen(const std::filesystem::path &path, accesstype type, transfermode mode) {
    ftphandle_t datahandle;
    if (this->FtpAccess(path, type, mode, m_handle, &datahandle) != FTPLIB_E_NONE) {
        return nullptr;
    }
    return datahandle;
}

int ftplib::RawClose(ftphandle_t handle) {
    return this->FtpClose(handle);
}

int ftplib::RawWrite(const void* buf, int len, ftphandle_t handle) {
    return this->FtpWrite(buf, len, handle);
}

int ftplib::RawRead(void* buf, int max, ftphandle_t handle) {
    return this->FtpRead(buf, max, handle);
}

void ftplib::update_errormsg(const std::string &prefix) {
    if (m_handle != nullptr) {
        m_handle->errormsg = prefix + ": " + strerror(errno);
    }
}

void ftplib::update_errormsg(ftphandle_t target, const std::string &prefix) {
    if (target != nullptr) {
        target->errormsg = prefix + ": " + strerror(errno);
    }
}