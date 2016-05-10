/*
 * Code taken and modified from https://curl.haxx.se/libcurl/c/10-at-a-time.html
 */
#include <stdio.h>
#include <string.h>
#include "../xmlparser/xmlparse.h"
/* somewhat unix-specific */ 
#include <sys/time.h>
#include <unistd.h>
/* curl stuff */ 
#include <curl/curl.h>
#include "../common/log.h"

static const char *urls[] = {
  "http://www.microsoft.com",
  "http://www.opensource.org",
  "http://www.google.com",
  "http://www.yahoo.com",
  "http://www.ibm.com",
};
#define CNT sizeof(urls)/sizeof(char*)  
#define MAX_PARALLEL 100

/*
 * Called for data recvd, via CURLOPT_WRITEFUNCTION
 */
static size_t cb(char *d, size_t n, size_t l, void *p)
{
  /* take care of the data here, ignored in this example */ 
  (void)d;
  (void)p;
  return n*l;
}

CURL* init(CURLM *cm, int i) {
  CURL *eh = curl_easy_init();
 
  //curl_easy_setopt(eh, CURLOPT_WRITEFUNCTION, cb);
  curl_easy_setopt(eh, CURLOPT_HEADER, 0L);
  curl_easy_setopt(eh, CURLOPT_URL, urls[i]);
  curl_easy_setopt(eh, CURLOPT_PRIVATE, urls[i]);
  curl_easy_setopt(eh, CURLOPT_VERBOSE, 0L);
 
  curl_multi_add_handle(cm, eh);
	return eh;
}

int curl_main(xmlData_t *xmlData, FILE *fhttpStats, FILE *fp)
{
  CURL *handles[MAX_PARALLEL];
  CURLM *multi_handle;
  int C;
  int still_running; /* keep number of running handles */ 
  int i;
  CURLMsg *msg; /* for picking up messages with the transfer status */ 
  int msgs_left; /* how many messages are left */ 
  int httpParallel = xmlData->httpParallel;

  /* init a multi stack */ 
  multi_handle = curl_multi_init();
 
  /* Allocate one CURL handle per transfer */ 
  for(i=0; i<httpParallel; i++)
		handles[i] = init(multi_handle, i);
 
  /* we start some action by calling perform right away */ 
  curl_multi_perform(multi_handle, &still_running);
 
  do {
    struct timeval timeout;
    int rc; /* select() return code */ 
    CURLMcode mc; /* curl_multi_fdset() return code */ 
 
    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;
 
    long curl_timeo = -1;
 
    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);
 
    /* set a suitable timeout to play around with */ 
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
 
    curl_multi_timeout(multi_handle, &curl_timeo);
    if(curl_timeo >= 0) {
      timeout.tv_sec = curl_timeo / 1000;
      if(timeout.tv_sec > 1)
        timeout.tv_sec = 1;
      else
        timeout.tv_usec = (curl_timeo % 1000) * 1000;
    }
 
    /* get file descriptors from the transfers */ 
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);
 
    if(mc != CURLM_OK) {
      log_error(fp, "curl_multi_fdset() failed, code %d.\n", mc);
      break;
    }
 
    /* On success the value of maxfd is guaranteed to be >= -1. We call
       select(maxfd + 1, ...); specially in case of (maxfd == -1) there are
       no fds ready yet so we call select(0, ...) --or Sleep() on Windows--
       to sleep 100ms, which is the minimum suggested value in the
       curl_multi_fdset() doc. */ 
 
    if(maxfd == -1) {
      struct timeval wait = { 0, 100 * 1000 }; /* 100ms */ 
      rc = select(0, NULL, NULL, NULL, &wait);
    } else {
      /* Note that on some platforms 'timeout' may be modified by select().
         If you need access to the original value save a copy beforehand. */ 
      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);
    }
 
    switch(rc) {
    case -1:
      /* select error */ 
      break;
    case 0: /* timeout */ 
    default: /* action */ 
      curl_multi_perform(multi_handle, &still_running);
      break;
    }
  } while(still_running);
 
  /* See how the transfers went */ 
  while((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
    if(msg->msg == CURLMSG_DONE) {
		char *url;
        CURL *e = msg->easy_handle;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &url);
        log_info(fp, "R: %d - %s <%s>\n",
                msg->data.result, curl_easy_strerror(msg->data.result), url);
        log_info(fhttpStats, "R: %d - %s <%s>\n",
                msg->data.result, curl_easy_strerror(msg->data.result), url);
        curl_multi_remove_handle(multi_handle, e);
        //curl_easy_cleanup(e);
      } else {
        log_error(fp, "E: CURLMsg (%d)\n", msg->msg);
      }	
  }
 
  curl_multi_cleanup(multi_handle);
 
  /* Free the CURL handles */ 
  for(i=0; i<httpParallel; i++)
    curl_easy_cleanup(handles[i]);
 
  return 0;
}
