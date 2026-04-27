#ifndef ATCA_CONFIG_H
#define ATCA_CONFIG_H

/** Enable support for ATECC608A */
#define ATCA_ATECC608A_SUPPORT

/** Enable support for ATECC608B (if using 608B variant) */
#define ATCA_ATECC608B_SUPPORT

/** Enable I2C HAL support */
#define ATCA_HAL_I2C

/** Disable other HAL types we don't use */
#undef ATCA_HAL_SWI
#undef ATCA_HAL_UART
#undef ATCA_HAL_SPI
#undef ATCA_HAL_KIT_HID
#undef ATCA_HAL_KIT_BRIDGE
#undef ATCA_HAL_CUSTOM

/** Enable basic commands */
#define ATCA_BASIC

/** Enable ECC operations */
#define ATCA_ECC_SUPPORT

/** Enable SHA operations */
#define ATCA_SHA_SUPPORT

/** Enable random number generation */
#define ATCA_RANDOM_SUPPORT

/** Use dynamic memory allocation (heap) */
#define ATCA_HEAP

/** Enable printf debug output (comment out to disable) */
#define ATCA_PRINTF

/** Maximum number of device instances */
#define ATCA_MAX_DEVICES    1

/** Default I2C address (7-bit) */
#define ATCA_I2C_DEFAULT_ADDRESS    0x60

/** Not using Linux */
#undef ATCA_HAL_LINUX

/** Not using Windows */
#undef ATCA_HAL_WIN

/** Embedded platform without RTOS */
#define ATCA_NO_RTOS

/** Custom HAL for Raspberry Pi Pico */
#define ATCA_HAL_CUSTOM_I2C

/** Disable features we don't need to reduce code size */
#undef ATCA_ATECC108A_SUPPORT
#undef ATCA_ATECC508A_SUPPORT
#undef ATCA_ATECC_SUPPORT
#undef ATCA_ATSHA204A_SUPPORT
#undef ATCA_ATSHA206A_SUPPORT
#undef ATCA_TA_SUPPORT
#undef ATCA_CA2_SUPPORT
#undef ATCA_ECC204_SUPPORT

/** Disable test/debug features */
#undef ATCA_TEST_MULTIPLE_INSTANCES
#undef ATCA_TRACE

/** Maximum packet size for I2C */
#define MAX_PACKET_SIZE     256

/** Serial number size (9 bytes for ATECC608) */
#define ATCA_SERIAL_NUM_SIZE    9

/** Random buffer size (32 bytes) */
#define ATCA_RANDOM_BUFFER_SIZE 32

/** Block size for read operations */
#define ATCA_BLOCK_SIZE         32

/** Key size (32 bytes for ECC P-256) */
#define ATCA_KEY_SIZE           32

/** Public key size (64 bytes for ECC P-256) */
#define ATCA_PUB_KEY_SIZE       64

/** Signature size (64 bytes for ECC P-256) */
#define ATCA_SIG_SIZE           64

/** Default wake delay in microseconds */
#define ATCA_WAKE_DELAY_US      1500

/** Post delay in milliseconds after wake (if POST enabled) */
#ifndef ATCA_POST_DELAY_MSEC
#define ATCA_POST_DELAY_MSEC 25
#endif

/** Default retry count for I2C operations */
#define ATCA_DEFAULT_RETRIES    20

/** Not using strict C99 mode */
#undef ATCA_STRICT_C99

/** Enable compiler optimizations */
#define ATCA_OPTIMIZE

#endif // ATCA_CONFIG_H