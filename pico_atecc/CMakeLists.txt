# Add External libraries subdirectory
add_subdirectory(external_lib/cryptoauthlib)
add_subdirectory(external_lib/no-OS-FatFS-SD-SPI-RPi-Pico/FatFs_SPI build)

# Create executable with all sources
add_executable(pico_atecc
    main.c
    # WiFi module
    wifi/wifi.c
    # SD card module
    sd_card/sd_card.c
    sd_card/hw_config.c
    # Webserver module
    webserver_pico/auth/http_auth.c
    webserver_pico/core/webserver_core.c
    webserver_pico/parse/http_parse.c
    webserver_pico/response/http_response.c
    webserver_pico/upload/http_upload.c
    webserver_pico/webserver/webserver_pico.c
    # ATECC608 modules
    atecc_script/password/password_verify.c
    atecc_script/sign_cert/cert_signing.c
    atecc_script/hal/hal_rp2040_i2c.c
    atecc_script/session_gen/session_key.c
    atecc_script/aes/aes_op.c
    atecc_script/init/atecc.c
    # Communication channel modules
    com_channel/channel/session/session_handle/session.c
    com_channel/channel/session/session_handle/fr_chan.c
    com_channel/channel/session/session_secure/fr_key.c
    com_channel/channel/session/session_end/system_kill.c
    com_channel/channel/aes/aes_helpers.c
    com_channel/channel/pico_auth/fr_auth.c
    com_channel/channel/user_auth/fr_pass.c
    com_channel/channel/base64/util_base64.c
    com_channel/channel/telemetry/fr_data.c
    com_channel/channel/telemetry/telem_decrypt_stream.c
    com_channel/cdc/fr_cdc.c
    # USB descriptors
    usb_desc/usb_descriptors.c
    # Rubber ducky execution
    rubber_exec/rubber_ducky.c
    # LED status
    led/led_status.c
)

# Set program name and version
pico_set_program_name(pico_atecc "pico_atecc")
pico_set_program_version(pico_atecc "0.1")

# Enable USB serial, disable UART
pico_enable_stdio_uart(pico_atecc 0)
pico_enable_stdio_usb(pico_atecc 1)

# Link libraries (combined from both projects)
target_link_libraries(pico_atecc
    pico_stdlib
    pico_unique_id
    pico_cyw43_arch_lwip_threadsafe_background
    pico_multicore
    hardware_i2c
    hardware_gpio
    hardware_spi
    hardware_dma
    tinyusb_device
    tinyusb_board
    cryptoauth
    FatFs_SPI
)

# Include directories for project files
target_include_directories(pico_atecc PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    # WiFi includes
    ${CMAKE_CURRENT_LIST_DIR}/wifi
    # SD card includes
    ${CMAKE_CURRENT_LIST_DIR}/sd_card
    # Webserver includes
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico/auth
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico/core
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico/parse
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico/response
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico/upload
    ${CMAKE_CURRENT_LIST_DIR}/webserver_pico/webserver
    # ATECC608 includes
    ${CMAKE_CURRENT_LIST_DIR}/atecc_script/password
    ${CMAKE_CURRENT_LIST_DIR}/atecc_script/sign_cert
    ${CMAKE_CURRENT_LIST_DIR}/atecc_script/hal
    ${CMAKE_CURRENT_LIST_DIR}/atecc_script/session_gen
    ${CMAKE_CURRENT_LIST_DIR}/atecc_script/aes
    ${CMAKE_CURRENT_LIST_DIR}/atecc_script/init
    # Communication channel includes
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/aes
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/base64
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/pico_auth
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/session
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/session/session_end
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/session/session_handle
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/session/session_secure
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/user_auth
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/channel/telemetry
    ${CMAKE_CURRENT_LIST_DIR}/com_channel/cdc
    # Other includes
    ${CMAKE_CURRENT_LIST_DIR}/usb_desc
    ${CMAKE_CURRENT_LIST_DIR}/rubber_exec
    ${CMAKE_CURRENT_LIST_DIR}/led
)

# Include directories for CryptoAuthLib
target_include_directories(cryptoauth PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/external_lib/cryptoauthlib/lib
    ${CMAKE_CURRENT_LIST_DIR}/external_lib/cryptoauthlib
)

# Compile definitions for CryptoAuthLib
target_compile_definitions(cryptoauth PUBLIC
    ATCA_HAL_I2C=1
    ATCA_ATECC608_SUPPORT=1
    ATCA_PRINTF=1
)

# Generate UF2, bin, hex
pico_add_extra_outputs(pico_atecc)