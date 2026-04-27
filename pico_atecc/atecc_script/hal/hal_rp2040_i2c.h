#ifndef ATECCX08_RPI_PICO_HAL_H
#define ATECCX08_RPI_PICO_HAL_H

#include "cryptoauthlib.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// HAL FUNCTION DECLARATIONS
// =============================================================================

/**
 * @brief Initialize I2C hardware for ATECC608 communication
 * @param iface Pointer to interface structure (provided by CryptoAuthLib)
 * @param cfg Pointer to interface configuration
 * @return ATCA_SUCCESS on successful initialization
 */
ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg* cfg);

/**
 * @brief Post-initialization operations (optional)
 * @param iface Pointer to interface structure
 * @return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface);

/**
 * @brief Transmit data packet to ATECC608
 * @param iface Pointer to interface structure
 * @param word_addr Word address or command identifier
 * @param txdata Pointer to transmit buffer
 * @param txlen Number of bytes to transmit
 * @return ATCA_SUCCESS on successful transmission
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_addr, 
                         uint8_t* txdata, int txlen);

/**
 * @brief Receive data packet from ATECC608
 * @param iface Pointer to interface structure
 * @param word_addr Device address to read from
 * @param rxdata Pointer to receive buffer
 * @param rxlen Pointer to expected/actual byte count
 * @return ATCA_SUCCESS on successful reception
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_addr,
                            uint8_t* rxdata, uint16_t* rxlen);

/**
 * @brief Control interface for wake/idle/sleep operations
 * @param iface Pointer to interface structure
 * @param opcode Control operation code
 * @param param Optional parameter data
 * @param paramlen Length of parameter data
 * @return ATCA_SUCCESS on successful operation
 */
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t opcode,
                            void* param, size_t paramlen);

/**
 * @brief Release HAL resources
 * @param hal_data HAL-specific data to release
 * @return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_release(void* hal_data);

/**
 * @brief Discover available I2C buses
 * @param buses_found Pointer to store count of discovered buses
 * @param max_buses Maximum buses to discover
 * @return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_discover_buses(int* buses_found, int max_buses);

/**
 * @brief Discover devices on specified I2C bus
 * @param bus_num Bus number to scan
 * @param devices_found Array to store discovered device addresses
 * @param max_devices Maximum devices to discover
 * @return ATCA_SUCCESS if devices found
 */
ATCA_STATUS hal_i2c_discover_devices(int bus_num, uint8_t* devices_found, 
                                     int max_devices);

// =============================================================================
// MEMORY MANAGEMENT INTERFACE
// =============================================================================

/**
 * @brief Allocate memory block
 * @param size Number of bytes to allocate
 * @return Pointer to allocated memory, or NULL on failure
 */
void* hal_malloc(size_t size);

/**
 * @brief Free allocated memory block
 * @param ptr Pointer to memory block to free
 */
void hal_free(void* ptr);

// =============================================================================
// TIMING INTERFACE
// =============================================================================

/**
 * @brief Delay execution for specified milliseconds
 * @param delay_ms Delay duration in milliseconds
 */
void hal_delay_ms(uint32_t delay_ms);

/**
 * @brief Delay execution for specified microseconds
 * @param delay_us Delay duration in microseconds
 */
void hal_delay_us(uint32_t delay_us);

// Legacy compatibility aliases
void atca_delay_ms(uint32_t ms);
void atca_delay_us(uint32_t us);

#ifdef __cplusplus
}
#endif

#endif // ATECCX08_RPI_PICO_HAL_H