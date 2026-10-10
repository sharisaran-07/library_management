#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "http.h"

static void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') &&
            ((a = src[1]) && (b = src[2])) &&
            (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a + b;
            src += 3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst = '\0';
}

int http_parse_request(const char* raw, int len, HttpRequest* req) {
    if (!raw || len <= 0 || !req) return 0;
    memset(req, 0, sizeof(HttpRequest));

    /* Parse request line */
    const char* line_end = strstr(raw, "\r\n");
    if (!line_end) line_end = strstr(raw, "\n");
    if (!line_end) return 0;

    char line[1024];
    int line_len = (int)(line_end - raw);
    if (line_len >= sizeof(line)) line_len = sizeof(line) - 1;
    strncpy(line, raw, line_len);
    line[line_len] = '\0';

    char url[MAX_PATH_LEN * 2];
    char version[32];
    if (sscanf(line, "%15s %1023s %31s", req->method, url, version) < 2) {
        return 0;
    }

    /* Split path and query */
    char* qmark = strchr(url, '?');
    if (qmark) {
        *qmark = '\0';
        url_decode(req->query, qmark + 1);
    }
    url_decode(req->path, url);

    /* Search headers */
    const char* header_start = line_end + (*line_end == '\r' ? 2 : 1);
    const char* body_start = strstr(raw, "\r\n\r\n");
    if (body_start) {
        body_start += 4;
    } else {
        body_start = strstr(raw, "\n\n");
        if (body_start) body_start += 2;
    }

    /* Content-Length */
    const char* cl = strstr(raw, "Content-Length:");
    if (!cl) cl = strstr(raw, "content-length:");
    if (!cl) cl = strstr(raw, "Content-length:");
    if (cl) {
        cl += 15;
        while (*cl == ' ' || *cl == '\t') cl++;
        req->content_length = atoi(cl);
    }

    /* Authorization header */
    const char* auth = strstr(raw, "Authorization: Bearer ");
    if (!auth) auth = strstr(raw, "authorization: Bearer ");
    if (auth) {
        auth += 22;
        int i = 0;
        while (*auth && *auth != '\r' && *auth != '\n' && i < sizeof(req->auth_token) - 1) {
            req->auth_token[i++] = *auth++;
        }
        req->auth_token[i] = '\0';
    }

    /* Check Cookie header if no Bearer token */
    if (strlen(req->auth_token) == 0) {
        const char* cookie = strstr(raw, "Cookie:");
        if (!cookie) cookie = strstr(raw, "cookie:");
        if (cookie) {
            const char* st = strstr(cookie, "session_token=");
            if (st) {
                st += 14;
                int i = 0;
                while (*st && *st != ';' && *st != '\r' && *st != '\n' && i < sizeof(req->auth_token) - 1) {
                    req->auth_token[i++] = *st++;
                }
                req->auth_token[i] = '\0';
            }
        }
    }

    /* User-Agent for device info */
    const char* ua = strstr(raw, "User-Agent: ");
    if (!ua) ua = strstr(raw, "user-agent: ");
    if (ua) {
        ua += 12;
        int i = 0;
        while (*ua && *ua != '\r' && *ua != '\n' && i < sizeof(req->device) - 1) {
            req->device[i++] = *ua++;
        }
        req->device[i] = '\0';
    }

    /* Parse Body */
    if (body_start && req->content_length > 0) {
        int avail_body = len - (int)(body_start - raw);
        int take_len = req->content_length;
        if (avail_body < take_len) take_len = avail_body;
        req->body = (char*)malloc(take_len + 1);
        if (req->body) {
            memcpy(req->body, body_start, take_len);
            req->body[take_len] = '\0';
        }
    }

    return 1;
}

void http_free_request(HttpRequest* req) {
    if (!req) return;
    if (req->body) {
        free(req->body);
        req->body = NULL;
    }
}

const char* http_get_mime_type(const char* path) {
    const char* ext = strrchr(path, '.');
    if (!ext) return "text/plain";
    if (strcasecmp(ext, ".html") == 0 || strcasecmp(ext, ".htm") == 0) return "text/html; charset=utf-8";
    if (strcasecmp(ext, ".css") == 0) return "text/css; charset=utf-8";
    if (strcasecmp(ext, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcasecmp(ext, ".json") == 0) return "application/json; charset=utf-8";
    if (strcasecmp(ext, ".png") == 0) return "image/png";
    if (strcasecmp(ext, ".jpg") == 0 || strcasecmp(ext, ".jpeg") == 0) return "image/jpeg";
    if (strcasecmp(ext, ".svg") == 0) return "image/svg+xml";
    if (strcasecmp(ext, ".ico") == 0) return "image/x-icon";
    if (strcasecmp(ext, ".pdf") == 0) return "application/pdf";
    if (strcasecmp(ext, ".csv") == 0) return "text/csv; charset=utf-8";
    return "text/plain";
}

void http_send_response(socket_t sock, int status_code, const char* status_text, const char* content_type, const char* body, int body_len) {
    char header[1024];
    int hlen = snprintf(header, sizeof(header),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type ? content_type : "text/plain", body_len);

    send(sock, header, hlen, 0);
    if (body && body_len > 0) {
        send(sock, body, body_len, 0);
    }
}

void http_send_json(socket_t sock, int status_code, const char* json_str) {
    const char* status_text = "OK";
    if (status_code == 201) status_text = "Created";
    else if (status_code == 400) status_text = "Bad Request";
    else if (status_code == 401) status_text = "Unauthorized";
    else if (status_code == 403) status_text = "Forbidden";
    else if (status_code == 404) status_text = "Not Found";
    else if (status_code == 429) status_text = "Too Many Requests";
    else if (status_code == 500) status_text = "Internal Server Error";

    int len = json_str ? (int)strlen(json_str) : 0;
    http_send_response(sock, status_code, status_text, "application/json; charset=utf-8", json_str, len);
}

void http_send_error(socket_t sock, int status_code, const char* message) {
    char json_buf[512];
    snprintf(json_buf, sizeof(json_buf), "{\"error\":true,\"message\":\"%s\"}", message ? message : "Error");
    http_send_json(sock, status_code, json_buf);
}

void http_send_options(socket_t sock) {
    const char* resp = 
        "HTTP/1.1 204 No Content\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization, X-Session-Token\r\n"
        "Access-Control-Max-Age: 86400\r\n"
        "Connection: close\r\n\r\n";
    send(sock, resp, (int)strlen(resp), 0);
}

void http_send_file(socket_t sock, const char* relpath) {
    /* Prevent directory traversal */
    if (strstr(relpath, "..")) {
        http_send_error(sock, 403, "Forbidden");
        return;
    }

    char filepath[MAX_PATH_LEN];
    /* Default root points to login.html */
    if (strcmp(relpath, "/") == 0 || strcmp(relpath, "/login") == 0) {
        snprintf(filepath, sizeof(filepath), "web/login.html");
    } else if (strcmp(relpath, "/admin") == 0) {
        snprintf(filepath, sizeof(filepath), "web/admin.html");
    } else if (strcmp(relpath, "/librarian") == 0) {
        snprintf(filepath, sizeof(filepath), "web/librarian.html");
    } else if (strcmp(relpath, "/member") == 0) {
        snprintf(filepath, sizeof(filepath), "web/member.html");
    } else if (strcmp(relpath, "/gate") == 0) {
        snprintf(filepath, sizeof(filepath), "web/gate.html");
    } else {
        /* Prepend web/ if not already present */
        if (strncmp(relpath, "/web/", 5) == 0) {
            snprintf(filepath, sizeof(filepath), "%s", relpath + 1);
        } else if (relpath[0] == '/') {
            snprintf(filepath, sizeof(filepath), "web/%s", relpath + 1);
        } else {
            snprintf(filepath, sizeof(filepath), "web/%s", relpath);
        }
    }

    FILE* f = fopen(filepath, "rb");
    if (!f) {
        http_send_error(sock, 404, "File not found");
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* buffer = (char*)malloc(fsize);
    if (!buffer) {
        fclose(f);
        http_send_error(sock, 500, "Server memory allocation failed");
        return;
    }

    size_t read_bytes = fread(buffer, 1, fsize, f);
    fclose(f);

    const char* mime = http_get_mime_type(filepath);
    http_send_response(sock, 200, "OK", mime, buffer, (int)read_bytes);
    free(buffer);
}
