#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "server.h"
#include "http.h"
#include "api.h"

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#endif

typedef struct {
    socket_t client_sock;
} ClientContext;

#if defined(_WIN32)
static DWORD WINAPI handle_client_thread(LPVOID arg)
#else
static void* handle_client_thread(void* arg)
#endif
{
    ClientContext* ctx = (ClientContext*)arg;
    socket_t sock = ctx->client_sock;
    free(ctx);

    char header_buf[MAX_HTTP_HEADER];
    int total_read = 0;
    int header_end_pos = -1;

    /* Read until headers are complete */
    while (total_read < (int)sizeof(header_buf) - 1) {
        int bytes = recv(sock, header_buf + total_read, (int)sizeof(header_buf) - 1 - total_read, 0);
        if (bytes <= 0) break;
        total_read += bytes;
        header_buf[total_read] = '\0';

        char* marker = strstr(header_buf, "\r\n\r\n");
        if (marker) {
            header_end_pos = (int)(marker - header_buf) + 4;
            break;
        }
        marker = strstr(header_buf, "\n\n");
        if (marker) {
            header_end_pos = (int)(marker - header_buf) + 2;
            break;
        }
    }

    if (header_end_pos > 0) {
        /* Parse Content-Length from header (case-insensitive & whitespace-tolerant) */
        int content_len = 0;
        const char* cl = strstr(header_buf, "Content-Length:");
        if (!cl) cl = strstr(header_buf, "content-length:");
        if (!cl) cl = strstr(header_buf, "Content-length:");
        if (cl) {
            cl += 15;
            while (*cl == ' ' || *cl == '\t') cl++;
            content_len = atoi(cl);
        }

        /* Calculate total request size */
        int total_expected = header_end_pos + content_len;
        char* full_req = (char*)malloc(total_expected + 1);
        if (full_req) {
            memcpy(full_req, header_buf, total_read);
            int full_read = total_read;

            /* Read remaining body bytes if any */
            while (full_read < total_expected) {
                int bytes = recv(sock, full_req + full_read, total_expected - full_read, 0);
                if (bytes <= 0) break;
                full_read += bytes;
            }
            full_req[full_read] = '\0';

            HttpRequest req;
            if (http_parse_request(full_req, full_read, &req)) {
                if (strncmp(req.path, "/api/", 5) == 0) {
                    api_handle_request(sock, &req);
                } else {
                    http_send_file(sock, req.path);
                }
                http_free_request(&req);
            } else {
                http_send_error(sock, 400, "Malformed HTTP request");
            }
            free(full_req);
        }
    }

    #if defined(_WIN32)
    shutdown(sock, SD_SEND);
    char drain[256];
    while (recv(sock, drain, sizeof(drain), 0) > 0) {}
    closesocket(sock);
    return 0;
    #else
    shutdown(sock, SHUT_WR);
    char drain[256];
    while (recv(sock, drain, sizeof(drain), 0) > 0) {}
    close(sock);
    return NULL;
    #endif
}

int server_start(int port) {
    #if defined(_WIN32)
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
        return 0;
    }
    #endif

    socket_t server_sock = socket(AF_INET, SOCK_STREAM, 0);
    #if defined(_WIN32)
    if (server_sock == INVALID_SOCKET) {
        printf("Could not create socket: %d\n", WSAGetLastError());
        WSACleanup();
        return 0;
    }
    #else
    if (server_sock < 0) {
        perror("Could not create socket");
        return 0;
    }
    #endif

    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        #if defined(_WIN32)
        printf("Bind failed on port %d with error %d\n", port, WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        #else
        perror("Bind failed");
        close(server_sock);
        #endif
        return 0;
    }

    listen(server_sock, 64);
    printf("Library Management Server listening on http://localhost:%d\n", port);
    printf("Press Ctrl+C to stop the server.\n\n");

    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);

    while (1) {
        socket_t client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        #if defined(_WIN32)
        if (client_sock == INVALID_SOCKET) continue;
        #else
        if (client_sock < 0) continue;
        #endif

        ClientContext* ctx = (ClientContext*)malloc(sizeof(ClientContext));
        if (ctx) {
            ctx->client_sock = client_sock;
            #if defined(_WIN32)
            HANDLE thread = CreateThread(NULL, 0, handle_client_thread, ctx, 0, NULL);
            if (thread) CloseHandle(thread);
            #else
            pthread_t thread;
            if (pthread_create(&thread, NULL, handle_client_thread, ctx) == 0) {
                pthread_detach(thread);
            }
            #endif
        } else {
            #if defined(_WIN32)
            closesocket(client_sock);
            #else
            close(client_sock);
            #endif
        }
    }

    #if defined(_WIN32)
    closesocket(server_sock);
    WSACleanup();
    #else
    close(server_sock);
    #endif
    return 1;
}
