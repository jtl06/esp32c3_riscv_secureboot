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
#include <stdio.h>
#include <string.h>

static const char *TAG = "SBC";

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
  uint32_t offset = sizeof(sbc_header_t); // Skip the header itself!

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
    ESP_LOGE(TAG, "Invalid Magic: %08lx", hdr.magic);
    return false;
  }
  ESP_LOGI(TAG, "Header found. Version: %lu, Size: %lu", hdr.img_version,
           hdr.img_size);

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

  int ret =
      mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, struct_digest, 0, hdr.sig, 64);
  mbedtls_pk_free(&pk);

  if (ret != 0) {
    ESP_LOGE(TAG, "Signature Invalid: -0x%04x", -ret);
    return false;
  }

  ESP_LOGI(TAG, "Signature Verified. Booting...");

  // 6. The Jump
  esp_image_metadata_t data;
  const esp_partition_pos_t part_pos = {
      .offset = part->address + sizeof(sbc_header_t), // Skip our header!
      .size = part->size - sizeof(sbc_header_t),
  };

  if (esp_image_load(ESP_IMAGE_LOAD, &part_pos, &data) != ESP_OK) {
    ESP_LOGE(TAG, "Failed to load image");
    return false;
  }

  typedef void (*entry_point_t)(void);
  entry_point_t entry_point = (entry_point_t)data.image.entry_addr;
  ESP_LOGI(TAG, "Jumping to entry point: 0x%08x", (uint32_t)entry_point);
  entry_point();

  return true; // This line will not be reached if jump is successful
}

void app_main(void) {
  ESP_LOGI(TAG, "Secure Bootloader Started");

  if (verify_application()) {
    ESP_LOGI(TAG, "Application verified successfully. (Jump handled by "
                  "esp_image_load if successful, wait... actually "
                  "esp_image_load doesn't jump, it loads. We need to jump.)");
    // Wait, esp_image_load loads it. But we need to jump to it.
    // Actually, esp_image_load just verifies and loads headers? No, it loads
    // segments. But it doesn't jump. We need to use a different function to
    // jump or just use esp_restart() if we were replacing the bootloader. But
    // we are an APP. To jump to another app from an app, we usually use
    // esp_ota_set_boot_partition and restart? But we want to jump to a raw
    // address or use the 2nd stage bootloader features? The user instructions
    // said: "This loads the app into RAM and jumps". Let's check esp_image_load
    // documentation or source. Actually, looking at IDF, esp_image_load just
    // loads. We might need to call the entry point manually.
    // data.image.entry_addr

    // The jump is now handled inside verify_application if successful.
    // If verify_application returns true, it means the jump was attempted.
    // If it returns false, it means verification failed.
  } else {
    ESP_LOGE(TAG, "Verification Failed! Halting.");
  }

  while (1) {
    vTaskDelay(pdMS_TO_TICKS(1000));
  }
}
