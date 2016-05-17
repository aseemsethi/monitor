typedef unsigned short u16;
typedef unsigned short ushort;
typedef unsigned long u32;
typedef unsigned char u8;
typedef unsigned char uchar;

typedef struct {
    int state;
    int custID;
    char serverIP[30]; // Same for Ping and SSL server

	// SSL Params
	int sslPort;
    int sslPerSec;
	
	// SSL Perf Params
    int totalConn;
	int helloPerSec;
    int totalHello;

	// HTTP Params
    char url[255];
    int httpParallel;
    int httpSerial;
    int httpVerbose;
} jsonData_t;

