/**
 * hw_config.c
 * Hardware configuration for SD card SPI interface
 * This file is required by the no-OS-FatFS-SD-SPI library
 */

#include "hw_config.h"
#include "hardware/dma.h"

// SPI configuration for SD card
static spi_t spi_config = {
    .hw_inst = spi1,
    .miso_gpio = 12,
    .mosi_gpio = 11,  
    .sck_gpio = 10,
    .baud_rate = 100000,          // REDUCED: Start at 100 kHz for initialization (was 400kHz)
    .DMA_IRQ_num = DMA_IRQ_0,
    .set_drive_strength = true,   // ENABLED: Better signal integrity
    .mosi_gpio_drive_strength = GPIO_DRIVE_STRENGTH_12MA,  // INCREASED from 4MA
    .sck_gpio_drive_strength = GPIO_DRIVE_STRENGTH_12MA    // INCREASED from 4MA
};

// SD card configuration
static sd_card_t sd_card = {
    .pcName = "0:",               // Drive name
    .spi = &spi_config,           // Pointer to SPI config
    .ss_gpio = 13,                // Chip Select on GPIO 13
    
    // Card detect (not used)
    .use_card_detect = false,
    .card_detect_gpio = 0,        // Not used
    .card_detected_true = 0,      // Not used
    
    // Set drive strength for SS pin
    .set_drive_strength = true,   // ENABLED
    .ss_gpio_drive_strength = GPIO_DRIVE_STRENGTH_12MA  // INCREASED from 4MA
};

// Required functions for the library

size_t sd_get_num(void) {
    return 1; // We have 1 SD card
}

sd_card_t *sd_get_by_num(size_t num) {
    if (num == 0) {
        return &sd_card;
    }
    return NULL;
}

size_t spi_get_num(void) {
    return 1; // We have 1 SPI bus
}

spi_t *spi_get_by_num(size_t num) {
    if (num == 0) {
        return &spi_config;
    }
    return NULL;
}