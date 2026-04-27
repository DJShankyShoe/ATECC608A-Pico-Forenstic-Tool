#include "sd_card.h"
#include "pico/stdlib.h"
#include "hardware/spi.h"
#include "ff.h"
#include "hw_config.h"
#include <stdio.h>
#include <string.h>

// Global FatFs objects
static FATFS fs;
static bool mounted = false;

// Helper: Get full file path
static void get_full_path(const char *filename, char *filepath, size_t max_len) {
    sd_card_t *pSD = sd_get_by_num(0);
    if (pSD) {
        snprintf(filepath, max_len, "%s/%s", pSD->pcName, filename);
    }
}

bool sd_init(void) {
    printf("Initializing SD card...\n");
    
    // Longer initial delay for SD card power-up
    sleep_ms(500);
    
    sd_card_t *pSD = sd_get_by_num(0);
    if (!pSD) {
        printf("ERROR: SD card configuration not found\n");
        return false;
    }
    
    printf("SD card config found\n");
    printf("  SPI: spi%d\n", spi_get_index(pSD->spi->hw_inst));
    printf("  SCK: GPIO %d\n", pSD->spi->sck_gpio);
    printf("  MOSI: GPIO %d\n", pSD->spi->mosi_gpio);
    printf("  MISO: GPIO %d\n", pSD->spi->miso_gpio);
    printf("  CS: GPIO %d\n", pSD->ss_gpio);
    printf("  Baud: %d Hz\n", pSD->spi->baud_rate);
    
    // Try to mount filesystem (with retries)
    printf("Attempting to mount SD card...\n");
    
    int retry_count = 3;
    FRESULT res = FR_NOT_READY;
    
    for (int i = 0; i < retry_count; i++) {
        if (i > 0) {
            printf("Retry attempt %d/%d...\n", i + 1, retry_count);
            sleep_ms(1000);
        }
        
        res = f_mount(&fs, pSD->pcName, 1);
        
        if (res == FR_OK) {
            printf("Mount successful!\n");
            break;
        } else {
            printf("Mount failed with error %d: ", res);
            switch(res) {
                case FR_NO_FILESYSTEM:
                    printf("No valid FAT filesystem found\n");
                    printf("  -> Format SD card as FAT32\n");
                    break;
                case FR_DISK_ERR:
                    printf("Low level disk I/O error\n");
                    printf("  -> Check wiring connections\n");
                    printf("  -> Check SD card is inserted properly\n");
                    break;
                case FR_NOT_READY:
                    printf("Storage device not ready\n");
                    printf("  -> SD card might be faulty\n");
                    break;
                case FR_NO_FILE:
                    printf("Could not find the file\n");
                    break;
                case FR_NO_PATH:
                    printf("Could not find the path\n");
                    break;
                default:
                    printf("Unknown error\n");
                    break;
            }
        }
    }
    
    if (res != FR_OK) {
        printf("\nFailed to mount SD card after %d attempts\n", retry_count);
        printf("\nTroubleshooting:\n");
        printf("1. Check SD card is inserted properly\n");
        printf("2. Verify SD card is formatted as FAT32 (not exFAT)\n");
        printf("3. Check wiring:\n");
        printf("   SCK  (Clock)     = GPIO %d\n", pSD->spi->sck_gpio);
        printf("   MOSI (Data Out)  = GPIO %d\n", pSD->spi->mosi_gpio);
        printf("   MISO (Data In)   = GPIO %d\n", pSD->spi->miso_gpio);
        printf("   CS   (Chip Sel)  = GPIO %d\n", pSD->ss_gpio);
        printf("4. Try a different SD card\n");
        printf("5. Check SD card works on PC first\n");
        return false;
    }
    
    mounted = true;
    printf("SD card mounted successfully\n");
    
    // Display storage info
    uint32_t total_kb, free_kb;
    if (sd_get_storage_info(&total_kb, &free_kb) == SD_OK) {
        printf("Storage: %lu KB total, %lu KB free (%.1f MB / %.1f MB)\n", 
               total_kb, free_kb, total_kb/1024.0f, free_kb/1024.0f);
    }
    
    return true;
}

bool sd_deinit(void) {
    if (!mounted) {
        return true;
    }
    
    sd_card_t *pSD = sd_get_by_num(0);
    if (!pSD) {
        return false;
    }
    
    FRESULT res = f_unmount(pSD->pcName);
    if (res != FR_OK) {
        printf("ERROR: Failed to unmount SD card (error %d)\n", res);
        return false;
    }
    
    mounted = false;
    printf("SD card unmounted\n");
    return true;
}

bool sd_is_mounted(void) {
    return mounted;
}

int sd_append_file(const char *filename, const uint8_t *data, size_t size) {
    if (!mounted) {
        printf("ERROR: SD card not mounted\n");
        return SD_NOT_MOUNTED;
    }
    
    if (!filename || !data || size == 0) {
        printf("ERROR: Invalid parameters\n");
        return SD_ERROR;
    }
    
    // Check available space
    uint32_t total_kb, free_kb;
    if (sd_get_storage_info(&total_kb, &free_kb) == SD_OK) {
        uint32_t needed_kb = (size + 1023) / 1024;
        if (needed_kb > free_kb) {
            printf("ERROR: Insufficient space (need %lu KB, have %lu KB)\n", 
                   needed_kb, free_kb);
            return SD_NO_SPACE;
        }
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FIL fil;
    FRESULT res = f_open(&fil, filepath, FA_WRITE | FA_OPEN_APPEND);
    if (res != FR_OK) {
        printf("ERROR: Failed to open file %s for append (error %d)\n", filename, res);
        return SD_FILE_ERROR;
    }
    
    UINT bw;
    res = f_write(&fil, data, size, &bw);
    f_sync(&fil);
    f_close(&fil);
    
    if (res != FR_OK || bw != size) {
        printf("ERROR: Failed to append to file %s (error %d, wrote %u/%zu bytes)\n",
               filename, res, bw, size);
        return SD_FILE_ERROR;
    }
    
    return SD_OK;
}

int sd_write_file(const char *filename, const uint8_t *data, size_t size) {
    if (!mounted) {
        printf("ERROR: SD card not mounted\n");
        return SD_NOT_MOUNTED;
    }
    
    if (!filename || !data || size == 0) {
        printf("ERROR: Invalid parameters\n");
        return SD_ERROR;
    }
    
    // Check available space
    uint32_t total_kb, free_kb;
    if (sd_get_storage_info(&total_kb, &free_kb) == SD_OK) {
        uint32_t needed_kb = (size + 1023) / 1024;  // Round up
        if (needed_kb > free_kb) {
            printf("ERROR: Insufficient space (need %lu KB, have %lu KB)\n", 
                   needed_kb, free_kb);
            return SD_NO_SPACE;
        }
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FIL fil;
    FRESULT res = f_open(&fil, filepath, FA_WRITE | FA_CREATE_ALWAYS);
    if (res != FR_OK) {
        printf("ERROR: Failed to create file %s (error %d)\n", filename, res);
        return SD_FILE_ERROR;
    }
    
    UINT bw;
    res = f_write(&fil, data, size, &bw);
    f_sync(&fil);
    f_close(&fil);
    
    if (res != FR_OK || bw != size) {
        printf("ERROR: Failed to write file %s (error %d, wrote %u/%zu bytes)\n",
               filename, res, bw, size);
        return SD_FILE_ERROR;
    }
    
    printf("Wrote %u bytes to %s\n", bw, filename);
    return SD_OK;
}

int sd_read_file(const char *filename, uint8_t *buffer, size_t buffer_size, size_t *bytes_read) {
    if (!mounted) {
        printf("ERROR: SD card not mounted\n");
        return SD_NOT_MOUNTED;
    }
    
    if (!filename || !buffer || !bytes_read) {
        printf("ERROR: Invalid parameters\n");
        return SD_ERROR;
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FIL fil;
    FRESULT res = f_open(&fil, filepath, FA_READ);
    if (res != FR_OK) {
        printf("ERROR: Failed to open file %s (error %d)\n", filename, res);
        return SD_FILE_ERROR;
    }
    
    UINT br;
    res = f_read(&fil, buffer, buffer_size, &br);
    *bytes_read = br;
    f_close(&fil);
    
    if (res != FR_OK) {
        printf("ERROR: Failed to read file %s (error %d)\n", filename, res);
        return SD_FILE_ERROR;
    }
    
    printf("Read %u bytes from %s\n", br, filename);
    return SD_OK;
}

int sd_delete_file(const char *filename) {
    if (!mounted) {
        printf("ERROR: SD card not mounted\n");
        return SD_NOT_MOUNTED;
    }
    
    if (!filename) {
        printf("ERROR: Invalid filename\n");
        return SD_ERROR;
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FRESULT res = f_unlink(filepath);
    if (res != FR_OK) {
        printf("ERROR: Failed to delete file %s (error %d)\n", filename, res);
        return SD_FILE_ERROR;
    }
    
    printf("Deleted file: %s\n", filename);
    return SD_OK;
}

int sd_list_files(void) {
    if (!mounted) {
        printf("ERROR: SD card not mounted\n");
        return SD_NOT_MOUNTED;
    }
    
    sd_card_t *pSD = sd_get_by_num(0);
    if (!pSD) return SD_ERROR;
    
    DIR dir;
    FILINFO fno;
    int file_count = 0;
    
    char dirpath[256];
    snprintf(dirpath, sizeof(dirpath), "%s/", pSD->pcName);
    
    FRESULT res = f_opendir(&dir, dirpath);
    if (res != FR_OK) {
        printf("ERROR: Failed to open directory (error %d)\n", res);
        return SD_ERROR;
    }
    
    printf("\nFiles on SD card:\n");
    printf("----------------------------------------\n");
    
    while (1) {
        res = f_readdir(&dir, &fno);
        if (res != FR_OK || fno.fname[0] == 0) {
            break;
        }
        
        if (!(fno.fattrib & AM_DIR)) {
            printf("  %-30s %10lu bytes\n", fno.fname, fno.fsize);
            file_count++;
        }
    }
    
    printf("----------------------------------------\n");
    printf("Total files: %d\n\n", file_count);
    
    f_closedir(&dir);
    return file_count;
}

int sd_get_file_list(sd_file_info_t *file_list, size_t max_files, size_t *file_count) {
    if (!mounted) {
        return SD_NOT_MOUNTED;
    }
    
    if (!file_list || !file_count) {
        return SD_ERROR;
    }
    
    sd_card_t *pSD = sd_get_by_num(0);
    if (!pSD) return SD_ERROR;
    
    DIR dir;
    FILINFO fno;
    size_t count = 0;
    
    char dirpath[256];
    snprintf(dirpath, sizeof(dirpath), "%s/", pSD->pcName);
    
    FRESULT res = f_opendir(&dir, dirpath);
    if (res != FR_OK) {
        return SD_ERROR;
    }
    
    while (count < max_files) {
        res = f_readdir(&dir, &fno);
        if (res != FR_OK || fno.fname[0] == 0) {
            break;
        }
        
        if (!(fno.fattrib & AM_DIR)) {
            strncpy(file_list[count].name, fno.fname, sizeof(file_list[count].name) - 1);
            file_list[count].size = fno.fsize;
            file_list[count].year = (fno.fdate >> 9) + 1980;
            file_list[count].month = (fno.fdate >> 5) & 0x0F;
            file_list[count].day = fno.fdate & 0x1F;
            file_list[count].hour = fno.ftime >> 11;
            file_list[count].minute = (fno.ftime >> 5) & 0x3F;
            count++;
        }
    }
    
    f_closedir(&dir);
    *file_count = count;
    return SD_OK;
}

bool sd_file_exists(const char *filename) {
    if (!mounted || !filename) {
        return false;
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FILINFO fno;
    FRESULT res = f_stat(filepath, &fno);
    return (res == FR_OK);
}

int sd_get_file_size(const char *filename, size_t *size) {
    if (!mounted) {
        return SD_NOT_MOUNTED;
    }
    
    if (!filename || !size) {
        return SD_ERROR;
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FILINFO fno;
    FRESULT res = f_stat(filepath, &fno);
    if (res != FR_OK) {
        return SD_FILE_ERROR;
    }
    
    *size = fno.fsize;
    return SD_OK;
}

int sd_get_storage_info(uint32_t *total_kb, uint32_t *free_kb) {
    if (!mounted) {
        return SD_NOT_MOUNTED;
    }
    
    if (!total_kb || !free_kb) {
        return SD_ERROR;
    }
    
    sd_card_t *pSD = sd_get_by_num(0);
    if (!pSD) return SD_ERROR;
    
    FATFS *fs_ptr;
    DWORD free_clusters;
    
    FRESULT res = f_getfree(pSD->pcName, &free_clusters, &fs_ptr);
    if (res != FR_OK) {
        return SD_ERROR;
    }
    
    DWORD total_sectors = (fs_ptr->n_fatent - 2) * fs_ptr->csize;
    DWORD free_sectors = free_clusters * fs_ptr->csize;
    
    *total_kb = (total_sectors * 512) / 1024;
    *free_kb = (free_sectors * 512) / 1024;
    
    return SD_OK;
}
// Streaming file access for large files
int sd_file_open(const char *filename, FIL *fil) {
    if (!mounted) {
        return SD_NOT_MOUNTED;
    }
    
    if (!filename || !fil) {
        return SD_ERROR;
    }
    
    char filepath[256];
    get_full_path(filename, filepath, sizeof(filepath));
    
    FRESULT res = f_open(fil, filepath, FA_READ);
    if (res != FR_OK) {
        return SD_FILE_ERROR;
    }
    
    return SD_OK;
}

int sd_file_read(FIL *fil, uint8_t *buffer, size_t bytes_to_read, size_t *bytes_read) {
    if (!fil || !buffer || !bytes_read) {
        printf("[SD] sd_file_read: Invalid params\n");
        fflush(stdout);
        return SD_ERROR;
    }
    
    printf("[SD] About to call f_read for %zu bytes...\n", bytes_to_read);
    fflush(stdout);
    
    UINT br;
    FRESULT res = f_read(fil, buffer, bytes_to_read, &br);
    
    printf("[SD] f_read returned: %d, bytes: %u\n", res, br);
    fflush(stdout);
    
    *bytes_read = br;
    
    if (res != FR_OK) {
        return SD_FILE_ERROR;
    }
    
    return SD_OK;
}

int sd_file_seek(FIL *fil, size_t offset) {
    if (!fil) {
        return SD_ERROR;
    }
    
    FRESULT res = f_lseek(fil, offset);
    if (res != FR_OK) {
        return SD_FILE_ERROR;
    }
    
    return SD_OK;
}

void sd_file_close(FIL *fil) {
    if (fil) {
        f_close(fil);
    }
}