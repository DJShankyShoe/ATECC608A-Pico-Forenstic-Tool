# Add CryptoAuthLib subdirectory
add_subdirectory(cryptoauthlib)

# Create executable with unified HAL
add_executable(attecc608_pico
    main.c
)

# Set program name and version
pico_set_program_name(attecc608_pico "attecc608_pico")
pico_set_program_version(attecc608_pico "0.1")

# Enable USB serial, disable UART
pico_enable_stdio_uart(attecc608_pico 0)
pico_enable_stdio_usb(attecc608_pico 1)

# Link libraries
target_link_libraries(attecc608_pico
    pico_stdlib
    hardware_i2c
    cryptoauth
)

# Include directories for project files
target_include_directories(attecc608_pico PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
)

# Include directories for CryptoAuthLib
target_include_directories(cryptoauth PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/cryptoauthlib/lib
    ${CMAKE_CURRENT_LIST_DIR}/cryptoauthlib
)

# Compile definitions for CryptoAuthLib
target_compile_definitions(cryptoauth PUBLIC
    ATCA_HAL_I2C=1
    ATCA_ATECC608_SUPPORT=1
    ATCA_PRINTF=1
)

# Generate UF2, bin, hex
pico_add_extra_outputs(attecc608_pico)