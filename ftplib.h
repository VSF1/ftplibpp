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
     std::string response;  // stores the response from the server
     std::string errormsg;  // stores the internal eror message
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
        accesstype_dir = 1,
        accesstype_dirverbose,
        accesstype_fileread,
        accesstype_filewrite,
        accesstype_filereadappend,
        accesstype_filewriteappend
    };

    enum transfermode {
        transfermode_ascii = 'A',
        transfermode_image = 'I'
    };

    enum connmode {
        connmode_pasv = 1,
        connmode_port
    };

    enum fxpmethod {
        fxpmethod_defaultfxp = 0,
        fxpmethod_alternativefxp
    };
 
    enum dataencryption {
        dataencryption_unencrypted = 0,
        dataencryption_secure
    };
 
    ftplib();
    virtual ~ftplib();

    const std::string last_response() noexcept;

    int connect(const std::string &host);

    bool is_connected() const noexcept;

    int login(const std::string &user, const std::string &pass);

    int site(const std::string &cmd);

    int raw(const std::string &cmd);

    int systype(std::string *buf);

    int mkdir(const std::string &path);

    int chdir(const std::string &path);

    int cdup();

    int rmdir(const std::string &path);

    int pwd(std::string *path);

    int nlst(const std::filesystem::path &outputfile, const std::string &path);
    int nlst(void *buffer, std::size_t size, const std::string &path);
    int nlst(std::string *str, const std::string &path);

    int dir(const std::filesystem::path &outputfile, const std::string &path);
    int dir(void *buffer, std::size_t size, const std::string &path);

    int size(const std::string &path, int *size, transfermode mode);

    int moddate(const std::string &path, std::string *dt);

    int get(const std::filesystem::path &outputfile, const std::string &path, transfermode mode, off64_t offset = 0);
    int get(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset = 0);

    int put(const std::filesystem::path &inputfile, const std::string &path, transfermode mode, off64_t offset = 0);
    int put(void *buffer, std::size_t size, const std::string &path, transfermode mode, off64_t offset = 0);

    int rename(const std::string &src, const std::string &dst);

    int del(const std::string &src);

    int quit();

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

    //
    /// @brief  Reads a line from the control connection.
    ///
    /// @param[out] buf A pointer to a std::string where the line is stored.
    /// @param[in]  ctl A pointer to a ftphandle containing the control connection.
    ///
    /// @returns The size of the line on success.
    ///         FTPLIB_E_ERROR on general error.
    ///         FTPLIB_E_INVALID_IO_OPERATION on io error.
    ssize_t read_line(std::string *buf, ftphandle_t ctl);
    ssize_t write_line(const std::string &buf, ftphandle_t hdata);
    ssize_t write_line(const char *buf, size_t len, ftphandle_t hdata);
    int read_resp(char c, ftphandle_t hcontrol);
    std::string sprint_rest(off64_t offset);
    void clear_handle(ftphandle_t handle);
    int correct_pasv_response(unsigned char *v);
 
    void ssl_init_lib();
    void ssl_init_handle();
    void ssl_term_handle();
 
    /// @brief Update the error message of the ftplib object
    void update_errormsg(const std::string &prefix = "");
 
    /// @brief Update the error message of the target object
    void update_errormsg(ftphandle_t target, const std::string &prefix = "");
 };
 
 #endif  // FTPLIB_H_
 