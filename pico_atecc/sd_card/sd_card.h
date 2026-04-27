/**
 * sd_card.h
 * SD Card Interface with FatFS
 */

#ifndef SD_CARD_H
#define SD_CARD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ff.h"  // FatFS file object

// Return codes
#define SD_OK              0
#define SD_ERROR          -1
#define SD_NOT_MOUNTED    -2
#define SD_FILE_ERROR     -3
#define SD_NO_SPACE       -4

// File information structure
typedef struct {
    char name[256];
    size_t size;
    uint16_t year;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
} sd_file_info_t;

/**
 * Initialize SD card and mount filesystem
 * @return true on success, false on failure
 */
bool sd_init(void);

/**
 * Deinitialize and unmount SD card
 * @return true on success, false on failure
 */
bool sd_deinit(void);

/**
 * Check if SD card is mounted
 * @return true if mounted, false otherwise
 */
bool sd_is_mounted(void);

/**
 * Write data to file (creates new file or overwrites existing)
 * @param filename Name of file to write
 * @param data Data to write
 * @param size Size of data in bytes
 * @return SD_OK on success, error code otherwise
 */
int sd_write_file(const char *filename, const uint8_t *data, size_t size);

/**
 * Append data to existing file (creates if doesn't exist)
 * @param filename Name of file to append to
 * @param data Data to append
 * @param size Size of data in bytes
 * @return SD_OK on success, error code otherwise
 */
int sd_append_file(const char *filename, const uint8_t *data, size_t size);

/**
 * Read entire file into buffer
 * @param filename Name of file to read
 * @param buffer Buffer to store data
 * @param buffer_size Size of buffer
 * @param bytes_read Actual number of bytes read
 * @return SD_OK on success, error code otherwise
 */
int sd_read_file(const char *filename, uint8_t *buffer, size_t buffer_size, size_t *bytes_read);

/**
 * Delete file
 * @param filename Name of file to delete
 * @return SD_OK on success, error code otherwise
 */
int sd_delete_file(const char *filename);

/**
 * Check if file exists
 * @param filename Name of file to check
 * @return true if file exists, false otherwise
 */
bool sd_file_exists(const char *filename);

/**
 * Get size of file
 * @param filename Name of file
 * @param size Pointer to store file size
 * @return SD_OK on success, error code otherwise
 */
int sd_get_file_size(const char *filename, size_t *size);

/**
 * List all files on SD card (prints to console)
 * @return Number of files found, or error code
 */
int sd_list_files(void);

/**
 * Get list of files on SD card
 * @param file_list Array to store file information
 * @param max_files Maximum number of files to return
 * @param file_count Actual number of files found
 * @return SD_OK on success, error code otherwise
 */
int sd_get_file_list(sd_file_info_t *file_list, size_t max_files, size_t *file_count);

/**
 * Get storage information (total and free space)
 * @param total_kb Total storage in KB
 * @param free_kb Free storage in KB
 * @return SD_OK on success, error code otherwise
 */
int sd_get_storage_info(uint32_t *total_kb, uint32_t *free_kb);

// ============================================================================
// STREAMING FILE ACCESS
// For reading large files chunk by chunk without loading entire file
// ============================================================================

/**
 * Open file for streaming read access
 * @param filename Name of file to open
 * @param fil FatFS file object (caller must provide)
 * @return SD_OK on success, error code otherwise
 */
int sd_file_open(const char *filename, FIL *fil);

/**
 * Read data from open file
 * @param fil Open file object
 * @param buffer Buffer to store data
 * @param bytes_to_read Number of bytes to read
 * @param bytes_read Actual number of bytes read
 * @return SD_OK on success, error code otherwise
 */
int sd_file_read(FIL *fil, uint8_t *buffer, size_t bytes_to_read, size_t *bytes_read);

/**
 * Seek to position in file
 * @param fil Open file object
 * @param offset Position to seek to (from start of file)
 * @return SD_OK on success, error code otherwise
 */
int sd_file_seek(FIL *fil, size_t offset);

/**
 * Close open file
 * @param fil File object to close
 */
void sd_file_close(FIL *fil);

#endif // SD_CARD_H