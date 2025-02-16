#include <cxxtest/TestSuite.h>
#include <fstream>
#include <string>
#include <vector>
#include <ftplib.h>

class ftp_client_tst : public CxxTest::TestSuite {
 public:
    void setUp() {
    }

    void testInvalidConnect() {
        ftplib *ftp = new ftplib();
        int ret;
        TS_ASSERT((ret = ftp->connect("")) == FTPLIB_E_ERROR);
        TS_ASSERT((ret = ftp->quit()) == FTPLIB_E_NO_ANSWER);
        delete ftp;
    }

    void testLogin() {
        int ret;
        ftplib *ftp = new ftplib();
        TS_ASSERT((ret = ftp->connect("cygwin.mirror.rafal.ca")) == FTPLIB_E_NONE);
        TS_ASSERT((ret = ftp->login("ftp", "email@example.com")) == FTPLIB_E_NONE);
        TS_ASSERT((ret = ftp->quit()) == FTPLIB_E_NONE);
        delete ftp;
    }

    void testDir() {
        ftplib *ftp = new ftplib();
        int ret;
        TS_ASSERT((ret = ftp->connect("cygwin.mirror.rafal.ca")) == FTPLIB_E_NONE);
        TS_ASSERT((ret = ftp->login("ftp", "email@example.com")) == FTPLIB_E_NONE);
        char *buffer = new char[5000];
        bzero(buffer, 5000);
        TS_ASSERT((ret = ftp->dir(buffer, 4999, "./")) == FTPLIB_E_NONE);
        TS_ASSERT((ret = ftp->quit()) == FTPLIB_E_NONE);
        // std::cout << buffer << std::endl;
        delete [] buffer;
        delete ftp;
    }

    void testDownload() {
        ftplib *ftp = new ftplib();
        int ret;
        TS_ASSERT((ret = ftp->connect("cygwin.mirror.rafal.ca")) == FTPLIB_E_NONE);
        TS_ASSERT((ret = ftp->login("ftp", "email@example.com")) == FTPLIB_E_NONE);
        char *buffer = new char[5000];
        TS_ASSERT((ret = ftp->get(buffer, 4999, "./robots.txt", ftplib::transfermode_image)) == FTPLIB_E_NONE);
        TS_ASSERT((ret = ftp->quit()) == FTPLIB_E_NONE);
        delete [] buffer;
        delete ftp;
    }

    void tearDown() {
    }
};

