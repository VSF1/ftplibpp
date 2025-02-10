#include <cxxtest/TestSuite.h>
#include <fstream>
#include <ftplib.h>

class ftp_client_tst : public CxxTest::TestSuite {
	std::string ftp_server = "127.0.0.1:21";
 public:
	void setUp() {
	}

    void testConnect() {
        ftplib *ftp = new ftplib();
        TS_ASSERT((ftp->connect("")) == FTPLIB_E_ERROR);
        std::cout << "error " << ftp->last_response() << std::endl;
        TS_ASSERT((ftp->connect("127.0.0.1")) == FTPLIB_E_ERROR);
        std::cout << "error " << ftp->last_response() << std::endl;
        delete ftp;
    }

    void testLogin() {
        ftplib *ftp = new ftplib();
        TS_ASSERT((ftp->connect(ftp_server)) == FTPLIB_E_ERROR);
        std::cout << "error " << ftp->last_response() << std::endl;
        TS_ASSERT((ftp->login("ftpuser", "ftpuser")) == FTPLIB_E_ERROR);
        delete ftp;
    }

    void tearDown() {   
    }
};
