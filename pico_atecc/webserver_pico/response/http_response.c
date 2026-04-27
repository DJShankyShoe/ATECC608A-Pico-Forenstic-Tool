#include "http_response.h"
#include "sd_card.h"
#include <stdio.h>
#include <string.h>

#define MAX_FILES_DISPLAY 30

static const char* http_html_hdr =
"HTTP/1.1 200 OK\r\n"
"Content-Type: text/html; charset=UTF-8\r\n"
"Connection: close\r\n"
"\r\n"
"<!DOCTYPE html><html><head>"
"<meta charset=\"UTF-8\">"
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
"<title>Pico W Files</title>"
"<style>"
"body{font-family:Arial;background:#667eea;margin:0;padding:20px}"
".c{background:#fff;padding:30px;border-radius:10px;max-width:800px;margin:0 auto}"
"h1{color:#333;text-align:center;margin:0 0 20px}"
".w{background:#fff3cd;padding:10px;border-radius:5px;margin-bottom:15px;font-size:14px}"
".i{background:#e9ecef;padding:12px;border-radius:5px;margin-bottom:15px;text-align:center}"
".u{background:#f8f9fa;padding:20px;border-radius:8px;margin-bottom:20px;border:2px dashed #667eea}"
".u h2{margin:0 0 15px;font-size:18px;color:#667eea}"
".u form{display:flex;flex-direction:column;gap:10px}"
".u input[type=file]{padding:8px;border:1px solid #ddd;border-radius:5px}"
".u input[type=submit]{background:#28a745;color:#fff;padding:10px;border:none;border-radius:5px;cursor:pointer;font-size:14px}"
".u input[type=submit]:hover{background:#218838}"
".f{background:#f8f9fa;padding:12px;margin:8px 0;border-radius:5px;display:flex;justify-content:space-between;align-items:center}"
".f:hover{background:#e9ecef}"
".b{display:flex;gap:8px}"
"a{background:#667eea;color:#fff;padding:6px 15px;border-radius:5px;text-decoration:none;font-size:13px}"
"a:hover{background:#5568d3}"
".d{background:#dc3545;}"
".d:hover{background:#c82333}"
".e{text-align:center;padding:30px;color:#999}"
"</style></head><body><div class='c'>"
"<h1>📁 Pico W Files</h1>";

static const char* http_html_ftr =
"<script>setTimeout(function(){location.reload()},30000)</script>"
"</div></body></html>";

int http_response_homepage(char* buffer, size_t buffer_size) {
    int offset = 0;

    offset += snprintf(buffer + offset, buffer_size - offset, "%s", http_html_hdr);

    if (!sd_is_mounted()) {
        offset += snprintf(buffer + offset, buffer_size - offset,
            "<div class='e'>💾 SD Card Not Available</div>");
        offset += snprintf(buffer + offset, buffer_size - offset, "%s", http_html_ftr);
        return offset;
    }

    uint32_t total_kb, free_kb;
    if (sd_get_storage_info(&total_kb, &free_kb) == SD_OK) {
        float used_pct = (total_kb > 0) ? (100.0f * (total_kb - free_kb) / total_kb) : 0;
        offset += snprintf(buffer + offset, buffer_size - offset,
            "<div class='i'>💾 %.0f MB free (%.0f%% used)</div>",
            free_kb / 1024.0f, used_pct);
    }

    offset += snprintf(buffer + offset, buffer_size - offset,
        "<div class='u'><h2>⬆️ Upload File</h2>"
        "<form method='POST' action='/upload' enctype='multipart/form-data'>"
        "<input type='file' name='file' required>"
        "<input type='submit' value='📤 Upload to SD Card'>"
        "</form></div>");

    sd_file_info_t files[MAX_FILES_DISPLAY];
    size_t file_count;

    if (sd_get_file_list(files, MAX_FILES_DISPLAY, &file_count) == SD_OK && file_count > 0) {
        offset += snprintf(buffer + offset, buffer_size - offset, "<div>");

        for (size_t i = 0; i < file_count && offset < buffer_size - 500; i++) {
            const char* icon = "📄";
            const char* note = "";
            const char* n = files[i].name;
            
            // Check for telemetry files
            if (strncmp(n, "telem_", 6) == 0 && strstr(n, ".dat")) {
                icon = "🔐";
                note = " <small style='color:#667eea'>(encrypted, auto-decrypt)</small>";
            }
            else if (strstr(n, ".txt")) icon = "📝";
            else if (strstr(n, ".json")) icon = "⚙️";
            else if (strstr(n, ".jpg") || strstr(n, ".png")) icon = "🖼️";
            else if (strstr(n, ".pdf")) icon = "📕";
            else if (strstr(n, ".csv")) icon = "📊";

            offset += snprintf(buffer + offset, buffer_size - offset,
                "<div class='f'><span>%s %s%s (%.1f KB)</span>"
                "<div class='b'><a href='/download?file=%s'>⬇️ Download</a>"
                "<a href='/delete?file=%s' class='d' onclick='return confirm(\"Delete %s?\")'>🗑️ Delete</a></div></div>",
                icon, files[i].name, note, files[i].size / 1024.0f, files[i].name, files[i].name, files[i].name);
        }
        offset += snprintf(buffer + offset, buffer_size - offset, "</div>");
    } else {
        offset += snprintf(buffer + offset, buffer_size - offset,
            "<div class='e'>📭 No files</div>");
    }

    offset += snprintf(buffer + offset, buffer_size - offset, "%s", http_html_ftr);
    return offset;
}

int http_response_file_download(const char* filename, uint8_t* file_buffer, size_t file_buffer_size, 
                                 char* response_buffer, size_t response_buffer_size) {
    if (!sd_is_mounted() || !sd_file_exists(filename)) {
        return -1;
    }

    size_t file_size;
    if (sd_get_file_size(filename, &file_size) != SD_OK) {
        return -1;
    }

    if (file_size > MAX_FILE_SIZE_WEB) {
        printf("[Response] File too large: %zu bytes\n", file_size);
        return -2;
    }

    size_t bytes_read;
    if (sd_read_file(filename, file_buffer, file_buffer_size, &bytes_read) != SD_OK) {
        return -1;
    }

    printf("[Response] Read %zu bytes from %s\n", bytes_read, filename);

    int offset = snprintf(response_buffer, response_buffer_size,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Disposition: attachment; filename=\"%s\"\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        filename, bytes_read);

    return offset;
}

int http_response_unauthorized(char* buffer, size_t buffer_size) {
    return snprintf(buffer, buffer_size,
        "HTTP/1.1 401 Unauthorized\r\n"
        "WWW-Authenticate: Basic realm=\"Pico W\"\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>401 Unauthorized</h1></body></html>");
}

int http_response_not_found(char* buffer, size_t buffer_size) {
    return snprintf(buffer, buffer_size,
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>404 Not Found</h1></body></html>");
}

int http_response_upload_success(char* buffer, size_t buffer_size) {
    return snprintf(buffer, buffer_size,
        "HTTP/1.1 303 See Other\r\n"
        "Location: /\r\n"
        "Connection: close\r\n"
        "\r\n");
}

int http_response_error(char* buffer, size_t buffer_size, const char* error_msg) {
    return snprintf(buffer, buffer_size,
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>500 Error</h1><p>%s</p></body></html>",
        error_msg);
}