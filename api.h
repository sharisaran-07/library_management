#ifndef API_H
#define API_H

#include "http.h"

void api_handle_request(socket_t sock, const HttpRequest* req);

#endif
