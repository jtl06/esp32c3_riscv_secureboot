idf_component_register(SRCS "main.c"
                        INCLUDE_DIRS "." "../../common/include"
                        REQUIRES mbedtls bootloader_support esp_partition log spi_flash esp_system)
