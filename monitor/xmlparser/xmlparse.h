typedef unsigned short u16;
typedef unsigned short ushort;
typedef unsigned long u32;
typedef unsigned char u8;
typedef unsigned char uchar;

typedef enum {
    START,
    CUSTID,
    SERVERIP,
    PING,
    PING_DURATION,
	SSL_PORT,
} state_p;

typedef struct {
    int state;
    int custID;
    char serverIP[30]; // Same for Ping and SSL server

	// Ping Params
    int pingTimer;
    int pingDuration;

	// SSL Params
	int sslPort;
} xmlData_t;

