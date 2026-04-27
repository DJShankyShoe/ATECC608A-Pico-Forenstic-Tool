// http_parse.c - HTTP Request Parsing Module Implementation
#include "http_parse.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

void http_parse_url_decode(char* dst, const char* src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) &&
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

size_t http_parse_content_length(const char* request) {
    const char* cl_header = strstr(request, "Content-Length:");
    if (!cl_header) {
        cl_header = strstr(request, "content-length:");
    }
    if (!cl_header) {
        return 0;
    }

    return atoi(cl_header + 15);  // Skip "Content-Length:"
}

bool http_parse_boundary(const char* request, char* boundary, size_t max_len) {
    const char* ct_header = strstr(request, "Content-Type:");
    if (!ct_header) {
        ct_header = strstr(request, "content-type:");
    }
    
    if (!ct_header) {
        return false;
    }

    const char* boundary_start = strstr(ct_header, "boundary=");
    if (!boundary_start) {
        return false;
    }

    boundary_start += 9;  // Skip "boundary="
    
    // Find end of boundary (space, newline, or semicolon)
    const char* boundary_end = boundary_start;
    while (*boundary_end && *boundary_end != ' ' && *boundary_end != '\r' && 
           *boundary_end != '\n' && *boundary_end != ';') {
        boundary_end++;
    }
    
    size_t len = boundary_end - boundary_start;
    if (len >= max_len) {
        len = max_len - 1;
    }
    
    strncpy(boundary, boundary_start, len);
    boundary[len] = '\0';
    
    printf("[HTTP Parse] Boundary: [%s]\n", boundary);
    
    return true;
}

bool http_parse_filename(const char* header, char* filename, size_t max_len) {
    const char* fn_start = strstr(header, "filename=\"");
    if (!fn_start) {
        return false;
    }

    fn_start += 10;  // Skip 'filename="'
    const char* fn_end = strchr(fn_start, '"');
    if (!fn_end) {
        return false;
    }

    size_t len = fn_end - fn_start;
    if (len >= max_len) {
        len = max_len - 1;
    }

    strncpy(filename, fn_start, len);
    filename[len] = '\0';
    
    return true;
}

int http_parse_multipart(const char* data, size_t data_len, const char* boundary,
                         char* filename, uint8_t** file_data, size_t* file_size) {
    printf("[HTTP Parse] Parsing multipart with boundary: [%s]\n", boundary);

    // Find Content-Disposition in the body
    const char* content_disp = strstr(data, "Content-Disposition:");
    if (!content_disp) {
        content_disp = strstr(data, "content-disposition:");
    }
    if (!content_disp) {
        printf("[HTTP Parse] No Content-Disposition found in body\n");
        return -1;
    }

    // Extract filename
    if (!http_parse_filename(content_disp, filename, 128)) {
        printf("[HTTP Parse] Failed to extract filename\n");
        return -1;
    }

    printf("[HTTP Parse] Filename: [%s]\n", filename);

    // Find end of part headers (double CRLF after Content-Disposition)
    const char* data_start = strstr(content_disp, "\r\n\r\n");
    if (!data_start) {
        printf("[HTTP Parse] No part header end found\n");
        return -1;
    }
    data_start += 4;  // Skip "\r\n\r\n"

    // Find end boundary
    char end_boundary[132];
    snprintf(end_boundary, sizeof(end_boundary), "\r\n--%s", boundary);
    const char* data_end = strstr(data_start, end_boundary);
    if (!data_end) {
        // Try without leading \r\n
        snprintf(end_boundary, sizeof(end_boundary), "--%s", boundary);
        data_end = strstr(data_start, end_boundary);
        if (!data_end) {
            printf("[HTTP Parse] No end boundary found\n");
            return -1;
        }
    }

    *file_data = (uint8_t*)data_start;
    *file_size = data_end - data_start;

    printf("[HTTP Parse] File size: %zu bytes\n", *file_size);

    return 0;
}

bool http_parse_method(const char* request, const char* method) {
    if (!request || !method) {
        return false;
    }
    
    size_t method_len = strlen(method);
    return (strncmp(request, method, method_len) == 0 && request[method_len] == ' ');
}

bool http_parse_path(const char* request, char* path, size_t max_len) {
    if (!request || !path) {
        return false;
    }
    
    // Find first space (after method)
    const char* path_start = strchr(request, ' ');
    if (!path_start) {
        return false;
    }
    path_start++;  // Skip space
    
    // Find second space (before HTTP version)
    const char* path_end = strchr(path_start, ' ');
    if (!path_end) {
        return false;
    }
    
    size_t len = path_end - path_start;
    if (len >= max_len) {
        len = max_len - 1;
    }
    
    strncpy(path, path_start, len);
    path[len] = '\0';
    
    return true;
}
