#ifndef WEBSERVER_PICO_H
#define WEBSERVER_PICO_H

#define TCP_PORT 8080

void start_tcp_server(void);
void webserver_set_auth(const char* username, const char* password);
void webserver_disable_auth(void);

#endif
