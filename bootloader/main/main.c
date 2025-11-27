#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "esp_image_format.h"
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "sbc_header.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static const char *TAG = "SBC";

#define MBEDTLS_MPI_CHK(f)                                                     \
  do {                                                                         \
    if ((ret = (f)) != 0)                                                      \
      goto cleanup;                                                            \
  } while (0)

const char *public_key_pem =
#include "public_key_include.h"
    ;

// Helper to calculate SHA-256 of the user partition
bool calc_app_hash(const esp_partition_t *partition, uint32_t data_len,
                   uint8_t *out_hash) {
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0); // 0 = SHA256

  uint8_t buf[1024];
  uint32_t left = data_len;
  uint32_t offset = 0x10000; // Skip the 64KB header + padding

  while (left > 0) {
    uint32_t to_read = (left > sizeof(buf)) ? sizeof(buf) : left;
    // Read from the user_app partition
    esp_err_t err = esp_partition_read(partition, offset, buf, to_read);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "Flash read error");
      return false;
    }
    mbedtls_sha256_update(&ctx, buf, to_read);
    offset += to_read;
    left -= to_read;
  }

  mbedtls_sha256_finish(&ctx, out_hash);
  mbedtls_sha256_free(&ctx);
  return true;
}

bool verify_application(void) {
  int ret = 0;
  // 1. Find the User App Partition
  const esp_partition_t *part =
      esp_partition_find_first(0x40, 0x00, "user_app");
  if (!part) {
    ESP_LOGE(TAG, "User partition not found!");
    return false;
  }

  // 2. Read the Header
  sbc_header_t hdr;
  if (esp_partition_read(part, 0, &hdr, sizeof(hdr)) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to read header");
    return false;
  }

  // 3. Verify Magic & Version
  if (hdr.magic != SBC_HEADER_MAGIC) {
    ESP_LOGE(TAG, "Invalid Magic: %08" PRIx32, hdr.magic);
    return false;
  }
  ESP_LOGI(TAG, "Header found. Version: %" PRIu32 ", Size: %" PRIu32,
           hdr.img_version, hdr.img_size);

  // 4. Calculate Hash of the binary
  uint8_t current_hash[32];
  calc_app_hash(part, hdr.img_size, current_hash);

  if (memcmp(current_hash, hdr.img_hash, 32) != 0) {
    ESP_LOGE(TAG, "Hash mismatch!");
    ESP_LOGE(TAG, "Expected: ");
    esp_log_buffer_hex(TAG, hdr.img_hash, 32);
    ESP_LOGE(TAG, "Calculated: ");
    esp_log_buffer_hex(TAG, current_hash, 32);
    return false;
  }
  ESP_LOGI(TAG, "Hash Verified.");

  // 5. Verify Signature (ECDSA)
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)public_key_pem,
                                  strlen(public_key_pem) + 1) != 0) {
    ESP_LOGE(TAG, "Key parse failed");
    return false;
  }

  // We verify the signature against the HASH of the header fields
  // (magic+size+ver+hash) This MUST match the packing logic in manager.py
  uint8_t struct_digest[32];
  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);
  mbedtls_sha256_starts(&sha_ctx, 0);
  mbedtls_sha256_update(&sha_ctx, (uint8_t *)&hdr.magic, sizeof(uint32_t));
  mbedtls_sha256_update(&sha_ctx, (uint8_t *)&hdr.img_size, sizeof(uint32_t));
  mbedtls_sha256_update(&sha_ctx, (uint8_t *)&hdr.img_version,
                        sizeof(uint32_t));
  mbedtls_sha256_update(&sha_ctx, hdr.img_hash, 32);
  mbedtls_sha256_finish(&sha_ctx, struct_digest);
  mbedtls_sha256_free(&sha_ctx);

  // Verify using low-level ECDSA to handle raw (r, s) signature
  mbedtls_mpi r, s;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  // Parse r and s from the 64-byte signature
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&r, hdr.sig, 32));
  MBEDTLS_MPI_CHK(mbedtls_mpi_read_binary(&s, hdr.sig + 32, 32));

  // Get the ECDSA context (ECP keypair)
  mbedtls_ecp_keypair *ctx = mbedtls_pk_ec(pk);

  // Verify
  ret = mbedtls_ecdsa_verify(&ctx->grp, struct_digest, 32, &ctx->Q, &r, &s);

cleanup:
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);
  mbedtls_pk_free(&pk);

  if (ret != 0) {
    ESP_LOGE(TAG, "Signature Invalid: -0x%04x", -ret);
    return false;
  }

  ESP_LOGI(TAG, "Signature Verified. Booting...");

  // 6. The Jump
  esp_image_metadata_t data;
  const esp_partition_pos_t part_pos = {
      .offset = part->address + 0x10000, // Skip 64KB header/padding
      .size = part->size - 0x10000,
  };

  // Use ESP_IMAGE_VERIFY because ESP_IMAGE_LOAD is not available in app build.
  // This verifies the image structure but does NOT load it into RAM.
  if (esp_image_verify(ESP_IMAGE_VERIFY, &part_pos, &data) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to verify image structure");
    return false;
  }

  typedef void (*entry_point_t)(void);
  entry_point_t entry_point = (entry_point_t)data.image.entry_addr;
  ESP_LOGI(TAG, "Jumping to entry point: 0x%08" PRIx32, (uint32_t)entry_point);

  // Note: Since we are an App, we cannot easily load the new app's segments
  // into IRAM/DRAM without potentially overwriting ourselves or messing up the
  // MMU. A real secure bootloader should be implemented as a 2nd stage
  // bootloader replacement. However, for this scaffold, we will attempt the
  // jump. If it fails, it confirms that we need to be a real bootloader or use
  // OTA mechanism.
  entry_point();

  return true;
}

void app_main(void) {
  ESP_LOGI(TAG, "Secure Bootloader Started");

  if (verify_application()) {
    ESP_LOGI(TAG, "Application verified successfully.");
  } else {
    ESP_LOGE(TAG, "Verification Failed! Halting.");
  }

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
