typedef struct {
    FILE *fp;
    FILE *fovStats;
    char selfIP[INET_ADDRSTRLEN];

    // Unit under test
    struct sockaddr_in server_addr;
    int sock;
    int seqNo;
} ovStruct_t;

