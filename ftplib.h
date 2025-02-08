/***************************************************************************
                          ftplib.h  -  description
                             -------------------
    begin                : Son Jul 27 2003
    copyright            : (C) 2013 by magnus kulke
    email                : mkulke@gmail.com
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License as        *
 *   published by the Free Software Foundation; either version 2.1 of the  *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 ***************************************************************************/

/***************************************************************************
 * Note: ftplib, on which ftplibpp was originally based upon used to be    *
 * licensed as GPL 2.0 software, as of Jan. 26th 2013 its author Thomas    *
 * Pfau allowed the distribution of ftplib via LGPL. Thus the license of   *
 * ftplibpp changed aswell.                                                *
 ***************************************************************************/

#ifndef FTPLIB_H_
#define FTPLIB_H_

#if defined(_WIN32)
    #if BUILDING_DLL
        # define DLLIMPORT __declspec (dllexport)
    #else /* Not BUILDING_DLL */
        # define DLLIMPORT __declspec (dllimport)
    #endif /* Not BUILDING_DLL */
    #include <time.h>
#endif

#include <string>
#include <filesystem>

#ifndef _WIN32
    #include <unistd.h>
#include <sys/time.h>

#define DLLIMPORT
#endif

#ifdef NOLFS
    #define off64_t long
    #define fseeko64 fseek
    #define fopen64 fopen
#endif

#if defined(__APPLE__)
    #define off64_t __darwin_off_t
    #define fseeko64 fseeko
    #define fopen64 fopen
#endif

#include <sys/types.h>

#define FTPLIB_OK                       (1)
#define FTPLIB_E_NONE                   (FTPLIB_OK)
#define FTPLIB_E_ERROR                  (0)
#define FTPLIB_E_INVALID_IO_OPERATION   (-1)
#define FTPLIB_E_SSL_NOT_SUPPORTED      (-100)
#define FTPLIB_E_NO_ANSWER              (-200)
#define FTPLIB_E_READ_FAILURE           (-201)

// SSL
typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;
typedef struct x509_st X509;

typedef int (*FtpCallbackXfer)(off64_t xfered, void *arg);
typedef int (*FtpCallbackIdle)(void *arg);
typedef void (*FtpCallbackLog)(const char *str, void* arg, bool out);
// SSL
typedef bool (*FtpCallbackCert)(void *arg, X509 *cert);

typedef struct ftphandle *ftphandle_t;

struct ftphandle {
    char *cput, *cget;
    int handle;
    int cavail, cleft;
    char *buf;
    int dir;
    ftphandle_t ctrl;
    int cmode;
    struct timeval idletime;
    FtpCallbackXfer xfercb;
    FtpCallbackIdle idlecb;
    FtpCallbackLog logcb;
    void *cbarg;
    off64_t xfered;
    off64_t cbbytes;
    off64_t xfered1;
    std::string response;
// SSL
    SSL* ssl;
    SSL_CTX* ctx;
    BIO* sbio;
    int tlsctrl;
    int tlsdata;
    FtpCallbackCert certcb;

    off64_t offset;
    bool correctpasv;
};

class DLLIMPORT ftplib {
 public:
    enum accesstype {
        dir = 1,
        dirverbose,
        fileread,
        filewrite,
        filereadappend,
        filewriteappend
    };

    enum transfermode {
        ascii = 'A',
        image = 'I'
    };

    enum connmode {
        pasv = 1,
        port
    };

    enum fxpmethod {
        defaultfxp = 0,
        alternativefxp
    };

    enum dataencryption {
        unencrypted = 0,
        secure
    };

    ftplib();
    virtual ~ftplib();

    const std::string LastResponse() noexcept;

    int Connect(const std::string &host);

    bool isConnected() const noexcept;

    int Login(const std::string &user, const std::string &pass);

    int Site(const std::string &cmd);

    int Raw(const std::string &cmd);

    int SysType(std::string *buf);

    int Mkdir(const std::string &path);

    int Chdir(const std::string &path);

    int Cdup();

    int Rmdir(const std::string &path);

    int Pwd(std::string *path);

    int Nlst(const std::filesystem::path &outputfile, const std::string &path);
    int Nlst(void *buffer, std::size_t size, const std::string &path);
    int Nlst(std::string *str, const std::string &path);

    int Dir(const std::filesystem::path &outputfile, const std::string &path);
    int Dir(void *buffer, std::size_t size, const std::string &path);

    int Size(const std::string &path, int *size, transfermode mode);

    int ModDate(const std::string &path, std::string *dt);

    int Get(const std::filesystem::path &outputfile, const std::string &path, transfermode mode, off64_t offset = 0);
    int Get(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset = 0);

    int Put(const std::filesystem::path &inputfile, const std::string &path, transfermode mode, off64_t offset = 0);
    int Put(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset = 0);


    int Rename(const std::string &src, const std::string &dst);

    int Delete(const std::string &src);

    int Quit();

    void SetCallbackIdleFunction(FtpCallbackIdle pointer);
    void SetCallbackLogFunction(FtpCallbackLog pointer);
    void SetCallbackXferFunction(FtpCallbackXfer pointer);
    void SetCallbackArg(void *arg);
    void SetCallbackBytes(off64_t bytes);
    void SetCorrectPasv();
    void UnsetCorrectPasv();
    void SetCallbackIdletime(int time);
    void SetConnmode(connmode mode);
    static int Fxp(ftplib *src, ftplib *dst, const std::string &pathSrc, const std::string &pathDst, transfermode mode,
            fxpmethod method);
    ftphandle_t RawOpen(const std::filesystem::path &path, accesstype type, transfermode mode);
    int RawClose(ftphandle_t handle);
    int RawWrite(const void* buf, int len, ftphandle_t handle);
    int RawRead(void* buf, int max, ftphandle_t handle);
    // SSL
    int SetDataEncryption(dataencryption enc);
    int NegotiateEncryption();
    void SetCallbackCertFunction(FtpCallbackCert pointer);

 private:
    ftphandle_t m_handle;

    int FtpXfer(void *buffer, size_t size, const std::string &path, ftphandle_t hcontrol, accesstype type,
            transfermode mode);
    int FtpXfer(const std::filesystem::path &localfile, const std::string &path, ftphandle_t hcontrol,
            accesstype type, transfermode mode);
    int FtpXfer(std::string *str, const std::string &path, ftphandle_t hcontrol, accesstype type, transfermode mode);

    int FtpOpenPasv(ftphandle_t hcontrol, ftphandle_t *hdata, transfermode mode, int dir, const std::string &cmd);
    int FtpSendCmd(const std::string &cmd, char expresp, ftphandle_t hcontrol);
    int FtpAcceptConnection(ftphandle_t hdata, ftphandle_t hcontrol);
    int FtpOpenPort(ftphandle_t ncontrol, ftphandle_t *hdata, transfermode mode, int dir, const std::string &cmd);
    std::size_t FtpRead(void *buf, size_t max, ftphandle_t hdata);
    std::size_t FtpRead(std::string *str, ftphandle_t hdata);
    size_t FtpWrite(const std::string &buf, ftphandle_t hdata);
    size_t FtpWrite(const void *buf, size_t len, ftphandle_t hdata);
    int FtpAccess(const std::string &path, accesstype type, transfermode mode, ftphandle_t hcontrol,
            ftphandle_t *hdata);
    int FtpClose(ftphandle_t hdata);

    /// @brief wait for socket to become ready
    ///
    /// @details This function waits until the socket is ready for reading or writing
    /// depending on the value of the ftphandle_t::dir member of the ftphandle_t
    /// object. If the ftphandle_t::idlecb member is not NULL, that function is called
    /// for each iteration of the loop, until the socket becomes ready, or the
    /// timeout is reached.
    ///
    /// @param[in] ctl the ftphandle_t object
    ///
    /// @returns FTPLIB_E_NONE if the socket is ready, FTPLIB_E_ERROR otherwise
    int socket_wait(ftphandle_t ctl);

    ///
    /// @brief  Reads a line from the control connection.
    ///
    /// @param[out] buf A pointer to a std::string where the line is stored.
    /// @param[in]  ctl A pointer to a ftphandle containing the control connection.
    ///
    /// @returns The size of the line on success.
    ///         FTPLIB_E_ERROR on general error.
    ///         FTPLIB_E_INVALID_IO_OPERATION on io error.
    ssize_t readline(std::string *buf, ftphandle_t ctl);
    ssize_t writeline(const std::string &buf, ftphandle_t hdata);
    ssize_t writeline(const char *buf, size_t len, ftphandle_t hdata);
    int readresp(char c, ftphandle_t hcontrol);
    std::string sprint_rest(off64_t offset);
    void clear_handle(ftphandle_t handle);
    int CorrectPasvResponse(unsigned char *v);

    void ssl_init_lib();
    void ssl_init_handle();
    void ssl_term_handle();
};

#endif  // FTPLIB_H_
