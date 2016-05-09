typedef unsigned short u16;
typedef unsigned short ushort;
typedef unsigned long u32;
typedef unsigned char u8;
typedef unsigned char uchar;

typedef enum {
    START,
    CUSTID,
    SERVERIP, SSL_PORT,
	SSL_PERSEC, TOTAL_CONN,
    HELLO_PERSEC, TOTAL_HELLO,
	HTTP_PARALLEL
} state_p;

typedef struct {
    int state;
    int custID;
    char serverIP[30]; // Same for Ping and SSL server

	// SSL Params
	int sslPort;
    int sslPerSec;
    int totalConn;
	int helloPerSec;
    int totalHello;
    int httpParallel;
} xmlData_t;

