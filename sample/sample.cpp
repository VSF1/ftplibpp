#include "ftplib.h"

int main(void) {
	ftplib *ftp = new ftplib();
	ftp->connect("ftp.gwdg.de:21");
	ftp->login("anonymous", "");
	ftp->dir(NULL, "/pub/linux/apache");
	ftp->quit();
    delete ftp;
	return 0;
}
