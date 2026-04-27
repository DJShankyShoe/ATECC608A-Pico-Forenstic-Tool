#include "webserver_pico.h"
#include "webserver_core.h"
#include "http_auth.h"
#include <stdio.h>

void start_tcp_server(void) {
    printf("[Webserver] Starting web server on port %d\n", TCP_PORT);
    webserver_core_start(TCP_PORT);
}

void webserver_set_auth(const char* username, const char* password) {
    http_auth_set_credentials(username, password);
}

void webserver_disable_auth(void) {
    http_auth_disable();
}
