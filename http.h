#ifndef HTTP_H
#define HTTP_H

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
typedef int socket_t;
#endif

#define MAX_HTTP_HEADER 8192
#define MAX_PATH_LEN 512
#define MAX_METHOD_LEN 16

typedef struct {
    char method[MAX_METHOD_LEN];
    char path[MAX_PATH_LEN];
    char query[MAX_PATH_LEN];
    char auth_token[128];
    char device[128];
    char* body;
    int content_length;
} HttpRequest;

int http_parse_request(const char* raw_request, int len, HttpRequest* req);
void http_free_request(HttpRequest* req);

void http_send_response(socket_t sock, int status_code, const char* status_text, const char* content_type, const char* body, int body_len);
void http_send_json(socket_t sock, int status_code, const char* json_str);
void http_send_error(socket_t sock, int status_code, const char* message);
void http_send_file(socket_t sock, const char* filepath);
void http_send_options(socket_t sock);

const char* http_get_mime_type(const char* path);

#endif
