#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#include <ngx_md5.h>
#include <openssl/sha.h>

#include <nginx_ssl_fingerprint.h>

// https://www.rfc-editor.org/rfc/rfc8701.html
#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))

// 升序排序
static int ja4_uint16_compare(const void *a, const void *b) {
    uint16_t val_a = *(const uint16_t*)a;
    uint16_t val_b = *(const uint16_t*)b;
    return (val_a > val_b) - (val_a < val_b);
}

// uint16转换为4位十六进制字符串
static void ja4_uint16_to_hex4(uint16_t val, unsigned char *buf) {
    static const char hex_chars[] = "0123456789abcdef";
    buf[0] = hex_chars[(val >> 12) & 0xf];
    buf[1] = hex_chars[(val >> 8) & 0xf];
    buf[2] = hex_chars[(val >> 4) & 0xf];
    buf[3] = hex_chars[val & 0xf];
}

// 在dst处追加uint8的字符串表示，返回新的指针位置
static inline unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n == 0) {
        *dst++ = '0';
        return dst;
    }
    
    // 计算位数
    uint8_t temp = n;
    int digits = 0;
    while (temp > 0) {
        digits++;
        temp /= 10;
    }
    
    // 从右到左填充数字
    dst += digits;
    unsigned char *end = dst;
    for (int i = 0; i < digits; i++) {
        *--dst = (n % 10) + '0';
        n /= 10;
    }
    
    return end;
}

// 在dst处追加uint16的字符串表示，返回新的指针位置
static inline unsigned char *append_uint16(unsigned char* dst, uint16_t n)
{
    if (n == 0) {
        *dst++ = '0';
        return dst;
    }
    
    // 计算位数
    uint16_t temp = n;
    int digits = 0;
    while (temp > 0) {
        digits++;
        temp /= 10;
    }
    
    // 从右到左填充数字
    dst += digits;
    unsigned char *end = dst;
    for (int i = 0; i < digits; i++) {
        *--dst = (n % 10) + '0';
        n /= 10;
    }
    
    return end;
}

// 在dst处追加uint32的字符串表示，返回新的指针位置
static inline unsigned char *append_uint32(unsigned char* dst, uint32_t n)
{
    if (n == 0) {
        *dst++ = '0';
        return dst;
    }
    
    // 计算位数
    uint32_t temp = n;
    int digits = 0;
    while (temp > 0) {
        digits++;
        temp /= 10;
    }
    
    // 从右到左填充数字
    dst += digits;
    unsigned char *end = dst;
    for (int i = 0; i < digits; i++) {
        *--dst = (n % 10) + '0';
        n /= 10;
    }
    
    return end;
}


// 解析fp_ja_data
int ngx_ssl_ja_data(ngx_connection_t *c)
{
    u_char *ptr = NULL, *data = NULL, *ja4_header_ptr = NULL, *ja4_cipher_ptr = NULL, *ja4_ext_ptr = NULL;
    size_t num = 0, i;
    uint16_t n;

    data = c->ssl->fp_ja_data.data;
    if (data == NULL) {
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    // ja3里，十六进制的内容转换为十进制，长度增加
    c->ssl->fp_ja3_str.len = c->ssl->fp_ja_data.len * 3;
    c->ssl->fp_ja3_str.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }
    c->ssl->fp_ja4_header.len = 20;
    c->ssl->fp_ja4_header.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_header.len);
    if (c->ssl->fp_ja4_header.data == NULL) {
        c->ssl->fp_ja4_header.len = 0;
        return NGX_ERROR;
    }
    c->ssl->fp_ja4_ext.len = c->ssl->fp_ja_data.len * 3;
    c->ssl->fp_ja4_ext.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_ext.len);
    if (c->ssl->fp_ja4_ext.data == NULL) {
        c->ssl->fp_ja4_ext.len = 0;
        return NGX_ERROR;
    }

    ptr = c->ssl->fp_ja3_str.data;
    ja4_header_ptr = c->ssl->fp_ja4_header.data;
    
    ja4_ext_ptr = c->ssl->fp_ja4_ext.data;
    
    // ja4: tcp
    *ja4_header_ptr++ = 't';

    // ja3/ja4: tls版本
    ptr = append_uint16(ptr, *(uint16_t*)data);
    *ptr++ = ',';
    if (*(uint16_t*)data == TLS1_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '0';
    } else if (*(uint16_t*)data == TLS1_1_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '1';
    } else if (*(uint16_t*)data == TLS1_2_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '2';
    } else if (*(uint16_t*)data == TLS1_3_VERSION) {
        *ja4_header_ptr++ = '1';
        *ja4_header_ptr++ = '3';
    }
    data += 2;

    // ja4: sni
    *ja4_header_ptr++ = *data++;

    // ja4: 加密套件字节数
    num = *(uint16_t*)data;
    c->ssl->fp_ja4_cipher.len = num / 2 * 4; // 0x0403(2bytes)转换为"0403"(4bytes)
    c->ssl->fp_ja4_cipher.data = ngx_pnalloc(c->pool, c->ssl->fp_ja4_cipher.len);
    if (c->ssl->fp_ja4_cipher.data == NULL) {
        c->ssl->fp_ja4_cipher.len = 0;
        return NGX_ERROR;
    }
    ja4_cipher_ptr = c->ssl->fp_ja4_cipher.data;

    
    // 密码套件数组(用于排序)
    uint16_t *cipher_array = ngx_pnalloc(c->pool, (num / 2) * sizeof(uint16_t));
    if (cipher_array == NULL) {
        return NGX_ERROR;
    }
    size_t cnt = 0;
    
    for (i = 2; i <= num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i + 1]);
        if (!IS_GREASE_CODE(n)) {
            // ja3: 加密套件
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
            
            // ja4: 加密套件待排序
            cipher_array[cnt++] = n;
        }
    }
    // 逗号分隔
    if (num >= 2) {
        // 覆盖
        *(ptr-1) = ',';
    } else {
        // 追加
        *(ptr++) = ',';
    }
    
    
    // ja4: 加密套件个数
    uint16_t cipher_count_truncated = cnt > 99 ? 99 : cnt;
    *ja4_header_ptr++ = (cipher_count_truncated / 10) + '0';
    *ja4_header_ptr++ = (cipher_count_truncated % 10) + '0';
    
    // ja4: 排序密码套件
    qsort(cipher_array, cnt, sizeof(uint16_t), ja4_uint16_compare);
    
    // ja4: 生成排序后的十六进制字符串
    for (i = 0; i < cnt; i++) {
        ja4_uint16_to_hex4(cipher_array[i], (unsigned char*)ja4_cipher_ptr);
        ja4_cipher_ptr += 4;
        if (i < cnt - 1) {
            *ja4_cipher_ptr++ = ',';
        }
    }
    
    // 加密套件处理完
    data += 2 + num;

    // ext 扩展
    num = *(uint16_t*)data;
    
    // 扩展数组
    uint16_t *ext_array = ngx_pnalloc(c->pool, (num / 2) * sizeof(uint16_t));
    if (ext_array == NULL) {
        return NGX_ERROR;
    }
    cnt = 0;
    
    for (i = 2; i <= num; i += 2) {
        n = *(uint16_t*)(data + i);
        if (!IS_GREASE_CODE(n)) {
            // ja3
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
            // ja4: 过滤两个字段
            if (n != 0x0000 && n != 0x0010) {
                ext_array[cnt++] = n;
            }
        }
    }
    
    if (num != 0) {
        *(ptr-1) = ',';
        data += 2 + num;
    } else {
        *(ptr++) = ',';
    }
    
    // ja4: 扩展类型长度
    uint16_t ext_count_truncated = cnt > 99 ? 99 : cnt;
    *ja4_header_ptr++ = (ext_count_truncated / 10) + '0';
    *ja4_header_ptr++ = (ext_count_truncated % 10) + '0';
    
    qsort(ext_array, cnt, sizeof(uint16_t), ja4_uint16_compare);
    
    // ja4: 生成排序后的十六进制字符串
    for (i = 0; i < cnt; i++) {
        ja4_uint16_to_hex4(ext_array[i], (unsigned char*)ja4_ext_ptr);
        ja4_ext_ptr += 4;
        if (i < cnt - 1) {
            *ja4_ext_ptr++ = ',';
        }
    }


    // ja3: groups 支持的椭圆曲线
    num = *(uint16_t*)data;
    for (i = 2; i < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        }
    }
    if (num != 0) {
        *(ptr-1) = ',';
        data += num;
    } else {
        *(ptr++) = ',';
    }

    // ja3: 支持的椭圆曲线点格式
    num = *(uint8_t*)data;
    for (i = 1; i < num; i++) {
        ptr = append_uint16(ptr, (uint16_t)data[i]);
        *ptr++ = '-';
    }
    if (num != 0) {
        data += num;
        *(ptr-1) = ',';
        *ptr-- = 0;
    }

    // ja4: alpn
    num = *(uint16_t*)data;
    if (num > 2) {
        size_t len = data[2];
        if (len == 0) {
            *ja4_header_ptr++ = '0';
            *ja4_header_ptr++ = '0';
        } else {
            // 长度异常
            if (2 + len >= num) {
                *ja4_header_ptr++ = '0';
                *ja4_header_ptr++ = '0';
            } else if (data[3] > 127) { // 字符异常
                *ja4_header_ptr++ = '9';
                *ja4_header_ptr++ = '9';
            } else {
                if (len == 1) {
                    *ja4_header_ptr++ = data[3];
                    *ja4_header_ptr++ = '0';
                } else {
                    *ja4_header_ptr++ = data[3];
                    *ja4_header_ptr++ = data[2 + len];
                }
            }
        }
    } else {
        *ja4_header_ptr++ = '0';
        *ja4_header_ptr++ = '0';
    }
    data += num;


    // ja4: 签名算法
    num = *(uint16_t*)data;
    if (num > 2) {
        uint16_t *algo_array = ngx_pnalloc(c->pool, (num / 2) * sizeof(uint16_t));
        if (algo_array == NULL) {
            return NGX_ERROR;
        }

        cnt = 0;

        for (i = 2; i < num; i += 2) {
            n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
            if (!IS_GREASE_CODE(n)) {
                algo_array[cnt++] = n;
            }
        }

        // 将算法拼接到扩展字段中
        if (cnt > 0) {
            // 检查扩展字段是否已有数据
            if (ja4_ext_ptr > c->ssl->fp_ja4_ext.data) {
                // 扩展字段有数据，用下划线连接
                *ja4_ext_ptr++ = '_';
            }
            
            // 生成排序后的算法十六进制字符串
            for (i = 0; i < cnt; i++) {
                ja4_uint16_to_hex4(algo_array[i], (unsigned char*)ja4_ext_ptr);
                ja4_ext_ptr += 4;
                if (i < cnt - 1) {
                    *ja4_ext_ptr++ = ',';
                }
            }
        }
    }
    data += num;
    
    c->ssl->fp_ja3_str.len = ptr - c->ssl->fp_ja3_str.data;
    c->ssl->fp_ja4_header.len = ja4_header_ptr - c->ssl->fp_ja4_header.data;
    c->ssl->fp_ja4_cipher.len = ja4_cipher_ptr - c->ssl->fp_ja4_cipher.data;
    c->ssl->fp_ja4_ext.len = ja4_ext_ptr - c->ssl->fp_ja4_ext.data;

    return NGX_OK;
}

// ja3 fp
int ngx_ssl_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t ctx;
    u_char hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(c->pool, c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }


    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}

// h2 fp
int ngx_http2_fingerprint(ngx_connection_t *c, ngx_http_v2_connection_t *h2c)
{
    unsigned char *pstr = NULL;
    unsigned short n = 0;
    size_t i;

    if (h2c->fp_str.len > 0) {
        return NGX_OK;
    }

    n = 4 + h2c->fp_settings.len * 3
        + 10 + h2c->fp_priorities.len * 2
        + h2c->fp_pseudoheaders.len * 2;

    h2c->fp_str.data = ngx_pnalloc(c->pool, n);
    if (h2c->fp_str.data == NULL) {
        /** Else we break a stream */
        return NGX_ERROR;
    }
    pstr = h2c->fp_str.data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: alloc bytes: [%d]\n", n);

    /* setting */
    for (i = 0; i < h2c->fp_settings.len; i+=5) {
        pstr = append_uint8(pstr, h2c->fp_settings.data[i]);
        *pstr++ = ':';
        pstr = append_uint32(pstr, *(uint32_t*)(h2c->fp_settings.data+i+1));
        *pstr++ = ';';
    }
    *(pstr-1) = '|';

    /* windows update */
    pstr = append_uint32(pstr, h2c->fp_windowupdate);
    *pstr++ = '|';

    /* priorities */
    for (i = 0; i < h2c->fp_priorities.len; i+=4) {
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+1]);
        *pstr++ = ':';
        pstr = append_uint8(pstr, h2c->fp_priorities.data[i+2]);
        *pstr++ = ':';
        pstr = append_uint16(pstr, (uint16_t)h2c->fp_priorities.data[i+3]+1);
        *pstr++ = ',';
    }
    *(pstr-1) = '|';

    /* fp_pseudoheaders */
    for (i = 0; i < h2c->fp_pseudoheaders.len; i++) {
        *pstr++ = h2c->fp_pseudoheaders.data[i];
        *pstr++ = ',';
    }

    /* null terminator */
    *--pstr = 0;

    h2c->fp_str.len = pstr - h2c->fp_str.data;

    h2c->fp_fingerprinted = 1;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, c->log, 0, "ngx_http2_fingerprint: http2 fingerprint: [%V], len=[%d]\n", &h2c->fp_str, h2c->fp_str.len);

    return NGX_OK;
}

// ja4_a
int ngx_ssl_ja4_header(ngx_connection_t *c)
{
    if (c->ssl->fp_ja4_header.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

// ja4_b原始字符串
int ngx_ssl_ja4_cipher(ngx_connection_t *c)
{
    if (c->ssl->fp_ja4_cipher.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

// ja4_c原始字符串
int ngx_ssl_ja4_ext(ngx_connection_t *c)
{
    if (c->ssl->fp_ja4_ext.len > 0) {
        return NGX_OK;
    }

    // JA4 ext通过ngx_ssl_ja_data计算
    if (ngx_ssl_ja_data(c) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

// ja4 fp
int ngx_ssl_ja4_hash(ngx_connection_t *c)
{
    SHA256_CTX sha256_ctx;
    
    if (c->ssl->fp_ja4_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja4_header(c) != NGX_OK ||
        ngx_ssl_ja4_cipher(c) != NGX_OK ||
        ngx_ssl_ja4_ext(c) != NGX_OK) {
        return NGX_ERROR;
    }

    // 计算cipher部分的SHA256哈希
    unsigned char cipher_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, c->ssl->fp_ja4_cipher.data, c->ssl->fp_ja4_cipher.len);
    SHA256_Final(cipher_hash, &sha256_ctx);
    
    // 将cipher哈希转换为十六进制字符串
    char cipher_hex[12] = {0};
    for (int i = 0; i < 6; i++) {
        sprintf(cipher_hex + i*2, "%02x", cipher_hash[i]);
    }

    // 计算extension部分的SHA256哈希
    unsigned char ext_hash[SHA256_DIGEST_LENGTH];
    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, c->ssl->fp_ja4_ext.data, c->ssl->fp_ja4_ext.len);
    SHA256_Final(ext_hash, &sha256_ctx);
    
    // 将extension哈希转换为十六进制字符串（前6个字节=12个字符）
    char ext_hex[12] = {0};
    for (int i = 0; i < 6; i++) {
        sprintf(ext_hex + i*2, "%02x", ext_hash[i]);
    }

    size_t total_len = c->ssl->fp_ja4_header.len + 1 + 12 + 1 + 12;
    
    c->ssl->fp_ja4_hash.data = ngx_pnalloc(c->pool, total_len + 1);
    if (c->ssl->fp_ja4_hash.data == NULL) {
        return NGX_ERROR;
    }

    // 拼接
    u_char *ptr = c->ssl->fp_ja4_hash.data;
    
    ngx_memcpy(ptr, c->ssl->fp_ja4_header.data, c->ssl->fp_ja4_header.len);
    ptr += c->ssl->fp_ja4_header.len;
    *ptr++ = '_';
    
    ngx_memcpy(ptr, cipher_hex, 12);
    ptr += 12;
    *ptr++ = '_';
    
    ngx_memcpy(ptr, ext_hex, 12);
    ptr += 12;
    
    c->ssl->fp_ja4_hash.len = ptr - c->ssl->fp_ja4_hash.data;

    return NGX_OK;
}
