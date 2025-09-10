
/*
 * Obj: nginx_ssl_fingerprint.c
 */

#ifndef NGINX_SSL_FINGERPRINT_H_
#define NGINX_SSL_FINGERPRINT_H_ 1


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

int ngx_ssl_ja_data(ngx_connection_t *c);
int ngx_ssl_ja3_hash(ngx_connection_t *c);
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c);

// JA4 相关函数
int ngx_ssl_ja4_header(ngx_connection_t *c);
int ngx_ssl_ja4_cipher(ngx_connection_t *c);
int ngx_ssl_ja4_ext(ngx_connection_t *c);
int ngx_ssl_ja4_hash(ngx_connection_t *c);

#endif /** NGINX_SSL_FINGERPRINT_H_ */

