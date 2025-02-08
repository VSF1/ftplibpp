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
#define _FTPLIB_SSL_CLIENT_METHOD_ openssl::TLSv1_2_client_method
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
    this->clear_handle(m_handle);
#ifndef NOSSL
    this->ssl_init_handle();
#endif
}

ftplib::~ftplib() {
    if (this->m_handle != nullptr) {
        this->Quit();
#ifndef NOSSL
        this->ssl_term_handle();
#endif
        if (this->m_handle->buf != nullptr) {
            std::free(this->m_handle->buf);
            this->m_handle->buf = nullptr;
        }
        std::free(this->m_handle);
        this->m_handle = nullptr;
    }
}

std::string ftplib::sprint_rest(off64_t offset) {
    return std::string("REST ") + std::to_string(offset);
}

/**
 * @brief wait for socket to become ready
 *
 * @details This function waits until the socket is ready for reading or writing
 * depending on the value of the ftphandle_t::dir member of the ftphandle_t
 * object. If the ftphandle_t::idlecb member is not NULL, that function is called
 * for each iteration of the loop, until the socket becomes ready, or the
 * timeout is reached.
 *
 * @param[in] ctl the ftphandle_t object
 *
 * @returns FTPLIB_E_NONE if the socket is ready, FTPLIB_E_ERROR otherwise
 */
int ftplib::socket_wait(ftphandle_t ctl) {
    fd_set fd, *rfd = NULL, *wfd = NULL;
    struct timeval tv;

    if (ctl->idlecb == NULL) {
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
            return FTPLIB_E_ERROR;
        } else if (rv > 0) {
            return FTPLIB_E_NONE;
        }
    } while ((rv = ctl->idlecb(ctl->cbarg)) == FTPLIB_E_NONE);
    return rv;
}

ssize_t ftplib::readline(std::string *buf, ftphandle_t ctl) {
    if ((ctl->dir != FTPLIB_CONTROL) && (ctl->dir != FTPLIB_READ)) {
        return FTPLIB_E_INVALID_IO_OPERATION;
    }
    if (buf == nullptr) {
        return FTPLIB_E_ERROR;
    }
    if (!buf->empty()) {
        buf->clear();
    }
    bool eof = false;
    size_t retval = 0;
    do {
        if (ctl->cavail > 0) {
            char *last = ::strchr(ctl->cget, '\n');
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

ssize_t ftplib::writeline(const std::string &buf, ftphandle_t hdata) {
    if (hdata == nullptr || hdata->dir != FTPLIB_WRITE) {
        return (-1);
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

ssize_t ftplib::writeline(const char *buf, size_t len, ftphandle_t hdata) {
    if (hdata == nullptr || hdata->dir != FTPLIB_WRITE) {
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
        if (!socket_wait(hdata)) {
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

int ftplib::readresp(char c, ftphandle_t hcontrol) {
    if (this->readline(&hcontrol->response, hcontrol) == FTPLIB_E_INVALID_IO_OPERATION) {
        ::perror("Control socket read failed");
        return FTPLIB_E_ERROR;
    }

    if (hcontrol->response[3] == '-') {
        std::string match = hcontrol->response.substr(0, 3) + " ";
        do {
            if (this->readline(&hcontrol->response, hcontrol) == FTPLIB_E_INVALID_IO_OPERATION) {
                ::perror("Control socket read failed");
                return FTPLIB_E_ERROR;
            }
        } while (hcontrol->response.substr(0, 4).compare(match) == 0);
    }

    return (hcontrol->response[0] == c) ? FTPLIB_E_NONE : FTPLIB_E_ERROR;
}

const std::string ftplib::LastResponse() noexcept {
    return ((this->m_handle) && (this->m_handle->dir == FTPLIB_CONTROL)) ? this->m_handle->response : std::string();
}

int ftplib::Connect(const std::string &host) {
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
    char *pnum = strchr(lhost, ':');
    if (pnum == NULL) {
        if ((pse = getservbyname("ftp", "tcp")) == NULL) {
            perror("getservbyname");
            std::free(lhost);
            return 0;
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
            perror("gethostbyname");
            std::free(lhost);
            return 0;
        }
        memcpy(reinterpret_cast<void *>(&sin.sin_addr), phe->h_addr, phe->h_length);
    }
    std::free(lhost);

    sControl = ::socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sControl == -1) {
        ::perror("socket");
        return 0;
    }

    if (::setsockopt(sControl, SOL_SOCKET, SO_REUSEADDR, SETSOCKOPT_OPTVAL_TYPE(&on), sizeof(on)) == -1) {
        ::perror("setsockopt");
        net_close(sControl);
        return 0;
    }
    if (::connect(sControl, reinterpret_cast<struct sockaddr *>(&sin), sizeof(sin)) == -1) {
        ::perror("connect");
        net_close(sControl);
        return 0;
    }

    m_handle->handle = sControl;

    if (this->readresp('2', m_handle) == 0) {
        net_close(sControl);
        m_handle->handle = 0;
        return 0;
    }

    return 1;
}

bool ftplib::isConnected() const noexcept {
    return (m_handle != nullptr && m_handle->handle != 0);
}

int ftplib::FtpSendCmd(const std::string &cmd, char expresp, ftphandle *hcontrol) {
    if ((!hcontrol->handle) || (hcontrol->dir != FTPLIB_CONTROL)) {
        return FTPLIB_E_ERROR;
    }

    int x;
    std::string buf = cmd + std::string("\r\n");
#ifndef NOSSL
    if (hcontrol->tlsctrl) {
        x = openssl::SSL_write(hcontrol->ssl, buf.c_str(), buf.length());
    } else {
        x = net_write(hcontrol->handle, buf.c_str(), buf.length());
    }
#else
    x = net_write(hcontrol->handle, buf.c_str(), buf.length());
#endif
    if (x <= 0) {
        perror("write");
        return FTPLIB_E_ERROR;
    }

    if (m_handle->logcb != nullptr) {
        m_handle->logcb(buf.c_str(), m_handle->cbarg, false);
    }
    return this->readresp(expresp, hcontrol);
}

int ftplib::Login(const std::string &user, const std::string &pass) {
    if (this->FtpSendCmd("USER " + user, '3', this->m_handle) != FTPLIB_E_NONE) {
        if (this->m_handle->ctrl != NULL || this->LastResponse()[0] == '2') {
            return FTPLIB_E_NONE;
        }
        return FTPLIB_E_ERROR;
    }
    return this->FtpSendCmd("PASS " + pass, '2', this->m_handle);
}

int ftplib::FtpAcceptConnection(ftphandle *hdata, ftphandle *hcontrol) {
    fd_set mask;
    FD_ZERO(&mask);
    FD_SET(hcontrol->handle, &mask);
    FD_SET(hdata->handle, &mask);
    struct timeval tv = {
        .tv_sec = ACCEPT_TIMEOUT,
        .tv_usec = 0
    };
    int fd = (hcontrol->handle < hdata->handle) ? hcontrol->handle : hdata->handle;
    int i = select(fd + 1, &mask, NULL, NULL, &tv);
    if (i == -1) {
        hcontrol->response = strerror(errno);
        net_close(hdata->handle);
        hdata->handle = 0;
        return FTPLIB_E_ERROR;
    } else if (i == 0) {
        hcontrol->response = "timed out waiting for connection";
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
                hdata->ctrl = hcontrol;
                return FTPLIB_E_NONE;
            } else {
                hcontrol->response = strerror(serrno);
                hdata->handle = 0;
                return FTPLIB_E_ERROR;
            }
        } else if (FD_ISSET(hcontrol->handle, &mask)) {
            net_close(hdata->handle);
            hdata->handle = 0;
            this->readresp('2', hcontrol);
            return FTPLIB_E_ERROR;
        }
    }
    return FTPLIB_E_ERROR;
}

int ftplib::FtpAccess(const std::string &path, accesstype type, transfermode mode, ftphandle_t hControl,
    ftphandle_t *hData) {
    int dir;

    if ((path.empty() || (hControl == nullptr)) &&
        ((type == ftplib::filewrite) || (type == ftplib::fileread) ||
         (type == ftplib::filereadappend) || (type == ftplib::filewriteappend))) {
        hControl->response = "Missing path argument for file transfer\n";
        return FTPLIB_E_ERROR;
    }

    std::string cmd = "TYPE ";
    cmd += mode;
    if (this->FtpSendCmd(cmd, '2', hControl) != FTPLIB_E_NONE) {
        return FTPLIB_E_ERROR;
    }

    switch (type) {
        case ftplib::dir:
            cmd = "NLST";
            dir = FTPLIB_READ;
            break;
        case ftplib::dirverbose:
            cmd = "LIST -aL";
            dir = FTPLIB_READ;
            break;
        case ftplib::filereadappend:
        case ftplib::fileread:
            cmd = "RETR";
            dir = FTPLIB_READ;
            break;
        case ftplib::filewriteappend:
        case ftplib::filewrite:
            cmd = "STOR";
            dir = FTPLIB_WRITE;
            break;
        default:
            hControl->response = "Invalid open type " + std::to_string(type) + "\n";
            return FTPLIB_E_ERROR;
        }

        if (!path.empty()) {
            cmd += " " + path;
        }

        if (hControl->cmode == ftplib::pasv) {
            if (FtpOpenPasv(hControl, hData, mode, dir, cmd) == -1) return 0;
        }

        if (hControl->cmode == ftplib::port) {
            if (FtpOpenPort(hControl, hData, mode, dir, cmd) == -1) return 0;
            if (!FtpAcceptConnection(*hData, hControl)) {
                this->FtpClose(*hData);
                *hData = nullptr;
                return FTPLIB_E_ERROR;
            }
    }

#ifndef NOSSL
    if (hControl->tlsdata) {
        (*hData)->ssl = openssl::SSL_new(hControl->ctx);
        (*hData)->sbio = openssl::BIO_new_socket((*hData)->handle, BIO_NOCLOSE);
        openssl::SSL_set_bio((*hData)->ssl, (*hData)->sbio, (*hData)->sbio);
        auto ret = openssl::SSL_connect((*hData)->ssl);
        if (ret != 1) {
            return 0;
        }
        (*hData)->tlsdata = 1;
    }
#endif
    return 1;
}

int ftplib::FtpOpenPort(ftphandle_t hcontrol, ftphandle_t *hdata, transfermode mode, int dir, const std::string &cmd) {
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
    } sin;
    struct linger lng = { 0, 0 };
    int on = 1;
    ftphandle *ctrl;

    if (hcontrol->dir != FTPLIB_CONTROL) {
        return (-1);
    }

    if ((dir != FTPLIB_READ) && (dir != FTPLIB_WRITE)) {
        hcontrol->response = "Invalid direction " + std::to_string(dir) + "\n";
        return (-1);
    }

    if ((mode != ftplib::ascii) && (mode != ftplib::image)) {
        hcontrol->response = "Invalid mode ";
        hcontrol->response += mode;
        hcontrol->response += "\n";
        return (-1);
    }

    socklen_t l = sizeof(sin);
    if (getsockname(hcontrol->handle, &sin.sa, &l) < 0) {
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
    if (!FtpSendCmd(buf, '2', hcontrol)) {
        net_close(sdata);
        return -1;
    }

    if (m_handle->offset != 0) {
            std::string s = sprint_rest(m_handle->offset);
            if (!FtpSendCmd(s, '3', hcontrol)) {
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

    if (!FtpSendCmd(cmd, '1', hcontrol)) {
        FtpClose(*hdata);
        *hdata = nullptr;
        return (-1);
    }

    ctrl->handle = sdata;
    ctrl->dir = dir;
    ctrl->ctrl = (hcontrol->cmode == ftplib::pasv) ? hcontrol : nullptr;
    ctrl->idletime = hcontrol->idletime;
    ctrl->cbarg = hcontrol->cbarg;
    ctrl->xfered = 0;
    ctrl->xfered1 = 0;
    ctrl->cbbytes = hcontrol->cbbytes;
    if (ctrl->idletime.tv_sec || ctrl->idletime.tv_usec) {
        ctrl->idlecb = hcontrol->idlecb;
    } else {
        ctrl->idlecb = nullptr;
    }

    if (ctrl->cbbytes) {
        ctrl->xfercb = hcontrol->xfercb;
    } else {
        ctrl->xfercb = nullptr;
    }

    *hdata = ctrl;

    return FTPLIB_E_NONE;
}

int ftplib::FtpOpenPasv(ftphandle_t hcontrol, ftphandle_t *hdata, transfermode mode, int dir, const std::string &cmd) {
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
    } sin;
    struct linger lng = { 0, 0 };
    unsigned int l;
    ftphandle *ctrl;
    unsigned char v[6];
    int ret;

    if (hcontrol->dir != FTPLIB_CONTROL) {
        return (-1);
    }

    if ((dir != FTPLIB_READ) && (dir != FTPLIB_WRITE)) {
        hcontrol->response = "Invalid direction " + std::to_string(dir) + "\n";
        return (-1);
    }
    if ((mode != ftplib::ascii) && (mode != ftplib::image)) {
        hcontrol->response = "Invalid mode ";
        hcontrol->response += std::to_string(mode);
        hcontrol->response = "\n";
        return (-1);
    }
    l = sizeof(sin);

    memset(&sin, 0, l);
    sin.in.sin_family = AF_INET;
    if (!FtpSendCmd("PASV", '2', hcontrol)) return (-1);
    size_t pos = hcontrol->response.find_first_of('(');
    if (pos == std::string::npos) return -1;
    const char *cp = &hcontrol->response[pos + 1];
#if defined(_WIN32)
    unsigned int v_i[6];
        sscanf(cp, "%u,%u,%u,%u,%u,%u", &v_i[2], &v_i[3], &v_i[4], &v_i[5], &v_i[0], &v_i[1]);
        for (int i = 0; i < 6; i++) v[i] = (unsigned char) v_i[i];
#else
    sscanf(cp, "%hhu,%hhu,%hhu,%hhu,%hhu,%hhu", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
#endif
    if (hcontrol->correctpasv) {
        if (!CorrectPasvResponse(v)) {
            return (-1);
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
        if (!FtpSendCmd(lcmd, '3', hcontrol)) {
            return (0);
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

    if (hcontrol->dir != FTPLIB_CONTROL) {
        return (-1);
    }

    std::string lcmd = cmd + "\r\n\0";
#ifndef NOSSL
    if (hcontrol->tlsctrl) {
        ret = openssl::SSL_write(hcontrol->ssl, lcmd.c_str(), lcmd.length());
    } else {
        ret = net_write(hcontrol->handle, lcmd.c_str(), lcmd.length());
    }
#else
    ret = net_write(hcontrol->handle, lcmd.c_str(), lcmd.length());
#endif
    if (ret <= 0) {
        perror("write");
        return (-1);
    }

    if (connect(sdata, &sin.sa, sizeof(sin.sa)) == -1) {
        perror("connect");
        net_close(sdata);
        return (-1);
    }

    if (!readresp('1', hcontrol)) {
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
    ctrl->ctrl = (hcontrol->cmode == ftplib::pasv) ? hcontrol : nullptr;
    ctrl->idletime = hcontrol->idletime;
    ctrl->cbarg = hcontrol->cbarg;
    ctrl->xfered = 0;
    ctrl->xfered1 = 0;
    ctrl->cbbytes = hcontrol->cbbytes;
    if (ctrl->idletime.tv_sec || ctrl->idletime.tv_usec) {
        ctrl->idlecb = hcontrol->idlecb;
    } else {
        ctrl->idlecb = nullptr;
    }
    if (ctrl->cbbytes) {
        ctrl->xfercb = hcontrol->xfercb;
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
            this->writeline("", hdata);
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
        return this->readresp('2', ctrl);
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
        i = this->readline(&lbuf, hdata);
        memcpy(buf, lbuf.c_str(), (max < lbuf.length() + 1) ? max : (lbuf.length() + 1));
    } else {
        if ((i = this->socket_wait(hdata)) != 1) {
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
    if (str == nullptr) {
        return FTPLIB_E_ERROR;
    }
    if (hdata == nullptr || hdata->dir != FTPLIB_READ) {
        return FTPLIB_E_ERROR;
    }

    char *buf = nullptr;
    int max = 1024;
    int i = -1;
    if (hdata->buf != nullptr) {
        i = this->readline(str, hdata);
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
        i = this->writeline(static_cast<const char*>(buf), hdata);
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

int ftplib::Site(const std::string &cmd) {
    std::string buf = std::string("SITE ") + cmd;
    if (!this->FtpSendCmd(buf, '2', m_handle)) {
        return (0);
    }
    return (1);
}

int ftplib::Raw(const std::string &cmd) {
    if (!this->FtpSendCmd(cmd, '2', m_handle)) return 0;
    return 1;
}

int ftplib::SysType(std::string *buf) {
    if (!this->FtpSendCmd("SYST", '2', m_handle)) {
        return (0);
    } else {
        std::string s = &m_handle->response[4];
        std::size_t pos = s.find_first_of(" ");
        if (pos == std::string::npos) {
            *buf = s;
        } else {
            *buf = s.substr(0, pos - 1);
        }
    }
    return (1);
}

int ftplib::Mkdir(const std::string &path) {
    std::string cmd = std::string("MKD ") + path;
    if (!this->FtpSendCmd(cmd, '2', m_handle)) return 0;
    return 1;
}

int ftplib::Chdir(const std::string &path) {
    std::string cmd = std::string("CWD ") + path;
    if (!this->FtpSendCmd(cmd, '2', m_handle)) return 0;
    return 1;
}

int ftplib::Cdup() {
    if (!this->FtpSendCmd("CDUP", '2', m_handle)) return 0;
    return 1;
}

int ftplib::Rmdir(const std::string &path) {
    std::string cmd = std::string("RMD ") + path;
    if (!this->FtpSendCmd(cmd, '2', m_handle)) return 0;
    return 1;
}

int ftplib::Pwd(std::string *path) {
    if (path == nullptr) {
        throw std::invalid_argument("path is nullptr");
    }

    if (!this->FtpSendCmd("PWD", '2', m_handle)) return 0;
    size_t pos;
    std::string s = m_handle->response;
    if ((pos = s.find_first_of('"')) == std::string::npos) {
        return 0;
    }
    s = s.substr(pos + 1);
    if ((pos = s.find_first_of('"')) == std::string::npos) {
        *path = s;
    } else {
        *path = s.substr(0, pos - 1);
    }
    return 1;
}

int ftplib::FtpXfer(void *buffer, size_t size, const std::string &path, ftphandle_t hcontrol, accesstype type,
                    transfermode mode) {
    char *dbuf;
    size_t size_remaining;
    ftphandle_t hdata;

    if (buffer == NULL || size == 0) {
        return 0;
    }

    if (type == ftplib::filewriteappend) {
        if (m_handle->offset < 0) return 0;
        size_t offset = m_handle->offset;
        dbuf = static_cast<char *>(buffer) + offset;
        size_remaining = size < offset ? 0 : size - offset;
    } else {
        dbuf = static_cast<char *>(buffer);
        size_remaining = size;
    }

    if (!this->FtpAccess(path, type, mode, hcontrol, &hdata)) {
        return 0;
        }

    if ((type == ftplib::filewrite) || (type == ftplib::filewriteappend)) {
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
            dbuf += c;
            size_remaining -= c;
            l = FTPLIB_BUFSIZ < size_remaining ? FTPLIB_BUFSIZ : size_remaining;
        }
    }
    return this->FtpClose(hdata);
}

int ftplib::FtpXfer(const std::filesystem::path &localfile, const std::string &path, ftphandle_t hcontrol,
            accesstype type, transfermode mode) {
    char *dbuf = nullptr;
    FILE *local = nullptr;
    ftphandle_t hdata = nullptr;

    if (localfile.empty() == false) {
        char ac[3] = "  ";
        if ((type == ftplib::dir) || (type == ftplib::dirverbose)) { ac[0] = 'w'; ac[1] = '\0'; }
        if (type == ftplib::fileread) { ac[0] = 'w'; ac[1] = '\0'; }
        if (type == ftplib::filewriteappend) { ac[0] = 'r'; ac[1] = '\0'; }
        if (type == ftplib::filereadappend) { ac[0] = 'a'; ac[1] = '\0'; }
        if (type == ftplib::filewrite) { ac[0] = 'r'; ac[1] = '\0'; }
        if (mode == ftplib::image) ac[1] = 'b';

        if ((local = fopen64(localfile.c_str(), ac)) == NULL) {
            hcontrol->response = strerror(errno);
            return 0;
        }
        if (type == ftplib::filewriteappend) {
            fseeko64(local, m_handle->offset, SEEK_SET);
        }
    }
    if (local == nullptr) {
        local = ((type == ftplib::filewrite) || (type == ftplib::filewriteappend)) ? stdin : stdout;
    }
    if (!this->FtpAccess(path, type, mode, hcontrol, &hdata)) {
        if (local != nullptr) {
            fclose(local);
            local = nullptr;
        }
        return 0;
    }

    dbuf = static_cast<char*>(std::malloc(FTPLIB_BUFSIZ));
    if ((type == ftplib::filewrite) || (type == ftplib::filewriteappend)) {
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
        while ((l = FtpRead(dbuf, FTPLIB_BUFSIZ, hdata)) > 0) {
            if (std::fwrite(dbuf, 1, l, local) == 0) {
                perror("localfile write");
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

int ftplib::FtpXfer(std::string *str, const std::string &path, ftphandle_t hcontrol, accesstype type,
                    transfermode mode) {
    ftphandle_t hdata;

    if (str == nullptr) {
        return 0;
    }

    if ((type == ftplib::filewriteappend) || (type == ftplib::filereadappend)) {
    } else {
        *str = "";
    }

    if (!this->FtpAccess(path, type, mode, hcontrol, &hdata)) {
        return 0;
    }

    if ((type == ftplib::filewrite) || (type == ftplib::filewriteappend)) {
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

int ftplib::Nlst(const std::filesystem::path &outputfile, const std::string &path) {
    m_handle->offset = 0;
    return FtpXfer(outputfile, path, m_handle, ftplib::dir, ftplib::ascii);
}

int ftplib::Nlst(void *buffer, std::size_t size, const std::string &path) {
    m_handle->offset = 0;
    return FtpXfer(buffer, size, path, m_handle, ftplib::dir, ftplib::ascii);
}

int ftplib::Nlst(std::string *str, const std::string &path) {
    m_handle->offset = 0;
    return FtpXfer(str, path, m_handle, ftplib::dir, ftplib::ascii);
}

/*
 * FtpDir - issue a LIST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Dir(const std::filesystem::path &outputfile, const std::string &path) {
    m_handle->offset = 0;
    return FtpXfer(outputfile, path, m_handle, ftplib::dirverbose, ftplib::ascii);
}

/*
 * FtpDir - issue a LIST command and write response to output
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Dir(void *buffer, std::size_t size, const std::string &path) {
    m_handle->offset = 0;
    return FtpXfer(buffer, size, path, m_handle, ftplib::dirverbose, ftplib::ascii);
}

int ftplib::Size(const std::string &path, int *size, transfermode mode) {
    std::string cmd = std::string("TYPE ");
    cmd += mode;

    if (!FtpSendCmd(cmd, '2', m_handle)) {
        return FTPLIB_E_ERROR;
    }

    cmd = std::string("SIZE ") + path;
    if (!FtpSendCmd(cmd, '2', m_handle)) {
        return FTPLIB_E_ERROR;
    }

    int resp, sz;
    if (sscanf(m_handle->response.c_str(), "%d %d", &resp, &sz) != 2) {
        return FTPLIB_E_ERROR;
    }

    *size = sz;
    return FTPLIB_E_NONE;
}

int ftplib::ModDate(const std::string &path, std::string *dt) {
    if (path.empty() || dt == nullptr) {
        return FTPLIB_E_ERROR;
    }
    if (!this->FtpSendCmd("MDTM " + path, '2', this->m_handle)) {
        return FTPLIB_E_ERROR;
    }
    *dt = this->m_handle->response.substr(4);
    return FTPLIB_E_NONE;
}

int ftplib::Get(const std::filesystem::path &outputfile, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(outputfile, path, m_handle, ((offset == 0) ? fileread : filereadappend), mode);
}

int ftplib::Get(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(buffer, size , path, m_handle, ((offset == 0) ? fileread : filereadappend), mode);
}

int ftplib::Put(const std::filesystem::path &inputfile, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(inputfile, path, m_handle, ((offset == 0) ? filewrite : filewriteappend), mode);
}

int ftplib::Put(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset) {
    m_handle->offset = offset;
    return this->FtpXfer(buffer, size, path, m_handle, ((offset == 0) ? filewrite : filewriteappend), mode);
}

int ftplib::Rename(const std::string &src, const std::string &dst) {
    if (!FtpSendCmd("RNFR " + src, '3', m_handle)) {
        return FTPLIB_E_ERROR;
    }
    if (!FtpSendCmd("RNTO " + dst, '2', m_handle)) {
        return FTPLIB_E_ERROR;
    }
    return FTPLIB_E_NONE;
}

int ftplib::Delete(const std::string &path) {
    if (!FtpSendCmd("DELE " + path, '2', m_handle)) {
        return FTPLIB_E_ERROR;
    }
    return FTPLIB_E_NONE;
}

/*
 * FtpQuit - disconnect from remote
 *
 * return 1 if successful, 0 otherwise
 */
int ftplib::Quit() {
    if (this->m_handle == nullptr || this->m_handle->dir != FTPLIB_CONTROL) {
        return FTPLIB_E_ERROR;
    }

    if (m_handle->handle == 0) {
        m_handle->response = "error: no anwser from server\n";
        return FTPLIB_E_NO_ANSWER;
    }

    int retval = FTPLIB_E_NONE;
    if (!FtpSendCmd("QUIT", '2', m_handle)) {
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
    if (!dst->FtpSendCmd(cmd, '2', dst->m_handle)) {
        return -1;
    }

    if (!src->FtpSendCmd(cmd, '2', src->m_handle)) {
        return -1;
    }

    if (method == ftplib::defaultfxp) {
        // PASV dst
        if (!dst->FtpSendCmd("PASV", '2', dst->m_handle)) {
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
            if (!dst->CorrectPasvResponse(v)) {
                return -1;
            }
        }

        // PORT src

        // sprintf(buf, "PORT %d,%d,%d,%d,%d,%d", v[2], v[3], v[4], v[5], v[0], v[1]);
        cmd = "PORT " + std::to_string(v[2]) + "," + std::to_string(v[3]) + "," + std::to_string(v[4]) + "," +
            std::to_string(v[5]) + "," + std::to_string(v[0]) + "," + std::to_string(v[1]);
        if (!src->FtpSendCmd(cmd, '2', src->m_handle)) {
            return -1;
        }

        // RETR src
        cmd = "RETR";
        if (pathSrc.length() > 0) {
            cmd += " " + pathSrc;
        }

        if (!src->FtpSendCmd(cmd, '1', src->m_handle)) {
            return 0;
        }

        // STOR dst
        cmd = "STOR";
        if (pathDst.length() > 0) {
                cmd += " " + pathDst;
        }

        if (!dst->FtpSendCmd(cmd, '1', dst->m_handle)) {
            /// this closes the data connection, to abort the RETR on the source ftp. all hail pftp, it took me several
            /// hours and i was absolutely clueless, playing around with ABOR and whatever, when i desperately checked
            /// the pftp source which gave me this final hint. thanks dude(s).
            dst->FtpSendCmd("PASV", '2', dst->m_handle);
            src->readresp('4', src->m_handle);
            return 0;
        }
        retval = (src->readresp('2', src->m_handle)) & (dst->readresp('2', dst->m_handle));
    } else {
        // PASV src
        if (!src->FtpSendCmd("PASV", '2', src->m_handle)) {
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
        if (src->m_handle->correctpasv) if (!src->CorrectPasvResponse(v)) return -1;

        // PORT dst
        cmd = "PORT " + std::to_string(v[2]) + "," + std::to_string(v[3]) + "," + std::to_string(v[4]) + "," +
            std::to_string(v[5]) + "," + std::to_string(v[0]) + "," + std::to_string(v[1]);
        if (!dst->FtpSendCmd(cmd, '2', dst->m_handle)) {
            return -1;
        }

        // STOR dest
        cmd = "STOR";
        if (!pathDst.empty()) cmd += " " + pathDst;
        if (!dst->FtpSendCmd(cmd, '1', dst->m_handle)) {
            return FTPLIB_E_ERROR;
        }

        // RETR src
        cmd = "RETR";
        if (!pathSrc.empty()) cmd += " " + pathSrc;
        if (!src->FtpSendCmd(cmd, '1', src->m_handle)) {
            src->FtpSendCmd("PASV", '2', src->m_handle);
            dst->readresp('4', dst->m_handle);
            return FTPLIB_E_ERROR;
        }

        // wait til its finished!
        retval = (src->readresp('2', src->m_handle)) & (dst->readresp('2', dst->m_handle));
    }

    return retval;
}

int ftplib::SetDataEncryption(dataencryption enc) {
#ifdef NOSSL
    (void)enc;
    return FTPLIB_E_SSL_NOT_SUPPORTED;
#else
    if (!m_handle->tlsctrl) return FTPLIB_E_ERROR;
    if (!FtpSendCmd("PBSZ 0", '2', m_handle)) return FTPLIB_E_ERROR;
    switch (enc) {
        case ftplib::unencrypted:
            m_handle->tlsdata = 0;
            if (!FtpSendCmd("PROT C", '2', m_handle)) return FTPLIB_E_ERROR;
            break;
        case ftplib::secure:
            m_handle->tlsdata = 1;
            if (!FtpSendCmd("PROT P", '2', m_handle)) return FTPLIB_E_ERROR;
            break;
        default:
            return FTPLIB_E_ERROR;
    }
    return FTPLIB_E_NONE;
#endif
}

int ftplib::NegotiateEncryption() {
#ifdef NOSSL
    return FTPLIB_E_SSL_NOT_SUPPORTED;
#else
    if (!FtpSendCmd("AUTH TLS", '2', m_handle)) {
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
        if (!m_handle->certcb(m_handle->cbarg, cert)) {
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
    handle->dir = FTPLIB_CONTROL;
    handle->ctrl = nullptr;
    handle->cmode = ftplib::pasv;
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

int ftplib::CorrectPasvResponse(unsigned char *v) {
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
