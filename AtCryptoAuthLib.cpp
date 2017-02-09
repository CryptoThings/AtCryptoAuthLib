
#include <stdint.h>
#include "AtCryptoAuthLib.h"
#include "atca_command.h"
#include "atcacert/atcacert_host_hw.h"

extern "C"
void hexdump(const void *buffer, uint32_t len, uint8_t cols);

extern const atcacert_def_t my_signer_cert_def;
extern const atcacert_def_t my_device_cert_def;

#ifdef LIB_DEBUG
#include <Arduino.h>

static char g_printf_buf[90];

#define AWS_PRINTF(...)  \
  { \
    snprintf(g_printf_buf, 90, __VA_ARGS__); \
    Serial.print(g_printf_buf); \
  }

#else

#define AWS_PRINTF(...)

#endif

// Get a pointer to the default configuration based on the compiler switch
#ifdef ATCA_HAL_KIT_CDC
ATCAIfaceCfg* gCfg = &cfg_ecc508_kitcdc_default;
#elif ATCA_HAL_KIT_HID
ATCAIfaceCfg* gCfg = &cfg_ecc508_kithid_default;
#else //#elif ATCA_HAL_I2C
ATCAIfaceCfg* gCfg = &cfg_ateccx08a_i2c_default;
#endif

AtCryptoAuthLib::AtCryptoAuthLib()
    : sha256_init(false)
{

}

AtCryptoAuthLib::~AtCryptoAuthLib()
{

}

ATCA_STATUS AtCryptoAuthLib::init(const uint8_t *access_key)
{
  ATCA_STATUS ret;
  ret = atcatls_init(gCfg);
  if (ret != ATCA_SUCCESS)
    return ret;

  if (access_key == NULL) {
    set_enc_key(ENC_KEY);
  } else {
    set_enc_key(access_key);
  }

  return atca_tls_init_enc_key();
}

ATCA_STATUS AtCryptoAuthLib::random(uint8_t rand_out[32])
{
  return atcatls_random(rand_out);
}

ATCA_STATUS AtCryptoAuthLib::get_pub_key(SlotCfg slot, uint8_t pubKey[64])
{
  return atcab_get_pubkey((uint16_t)slot, pubKey);
}

ATCA_STATUS AtCryptoAuthLib::gen_key(SlotCfg slot, uint8_t pubKey[64])
{
  return atcab_genkey((uint16_t)slot, pubKey);
}

ATCA_STATUS AtCryptoAuthLib::write_pub_key(SlotCfg slot, const uint8_t pubKey[64])
{
    return atcab_write_pubkey((uint16_t)slot, pubKey);
}

ATCA_STATUS AtCryptoAuthLib::sign(SlotCfg slot, const uint8_t to_sign[32], uint8_t signature[64])
{
  return atcab_sign((uint16_t)slot, to_sign, signature);
}

ATCA_STATUS AtCryptoAuthLib::sign(const uint8_t to_sign[32], uint8_t signature[64])
{
  return sign(AUTH_PRIV, to_sign, signature);
}

ATCA_STATUS AtCryptoAuthLib::verify(const uint8_t key[64], const uint8_t to_verify[32],
    const uint8_t signature[64], bool &verify_success)
{
  bool is_verif = false;
  ATCA_STATUS ret;
  ret = atcab_verify_extern(to_verify, signature, key, &is_verif);
  if (ret == ATCA_SUCCESS)
    verify_success = is_verif;

  return ret;
}

ATCA_STATUS AtCryptoAuthLib::verify(SlotCfg slot, const uint8_t to_verify[32],
    const uint8_t signature[64], bool &verify_success)
{
  ATCA_STATUS ret;
  uint8_t key[64];

  ret = get_pub_key(slot, key);
  if (ret != ATCA_SUCCESS) {
    return ret;
  }
  return verify(key, to_verify, signature, verify_success);
}

ATCA_STATUS AtCryptoAuthLib::verify(const uint8_t to_verify[64],
    const uint8_t signature[64], bool &verify_success)
{
  return verify(AUTH_PRIV, to_verify, signature, verify_success);
}
/* Doesn't work
ATCA_STATUS AtCryptoAuthLib::verify_stored(SlotCfg slot, const uint8_t to_verify[32],
    const uint8_t signature[64], bool &verify_success)
{
  bool is_verif = false;
  ATCA_STATUS ret;
  ret =  atcab_verify_stored(to_verify, signature, (uint16_t)slot, &is_verif);
  if (ret == ATCA_SUCCESS)
    verify_success = is_verif;

  return ret;
}
*/
ATCA_STATUS AtCryptoAuthLib::hash_start()
{
  ATCA_STATUS ret;
  if (sha256_init)
    return ATCA_BAD_PARAM;

  ret = (ATCA_STATUS)atcab_hw_sha2_256_init(&sha256_ctx);
  if (ret == ATCA_SUCCESS)
    sha256_init = true;

  return ret;
}

ATCA_STATUS AtCryptoAuthLib::hash_update(const uint8_t* data, size_t data_size)
{
  if (!sha256_init)
    return ATCA_BAD_PARAM;

  return (ATCA_STATUS)atcab_hw_sha2_256_update(&sha256_ctx, data, data_size);
}

ATCA_STATUS AtCryptoAuthLib::hash_finish(uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE])
{
  if (!sha256_init) {
    sha256_init = false;
    return ATCA_BAD_PARAM;
  }

  sha256_init = false;
  return (ATCA_STATUS)atcab_hw_sha2_256_finish(&sha256_ctx, digest);
}

ATCA_STATUS AtCryptoAuthLib::hash(const uint8_t* data, size_t data_size,
    uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE])
{
  ATCA_STATUS ret;
  ret = hash_start();
  if (ret != ATCA_SUCCESS)
    return ret;

  ret = hash_update(data, data_size);
  if (ret != ATCA_SUCCESS)
    return ret;

  return hash_finish(digest);
}

ATCA_STATUS AtCryptoAuthLib::hmac_start(uint8_t *hmac_key, size_t key_size)
{
  ATCA_STATUS ret;
  uint8_t pad[32];
  int i;
  if (sha256_init)
    return ATCA_BAD_PARAM;

  if (key_size > 32) {
    ret = atcab_hw_sha2_256(hmac_key, key_size, m_hmac_key);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: AtCryptoAuthLib::hmac_start @%d %d\n", __LINE__, ret);
      return ret;
    }
  } else {
    memset(m_hmac_key, 0, 32);
    memcpy(m_hmac_key, hmac_key, key_size);
  }
  memset(pad, 0x36, 32);
  for (i = 0; i < 32; i++)
    m_hmac_key[i] = m_hmac_key[i] ^ 0x36;

  ret = atcab_hw_sha2_256_init(&sha256_ctx);
  if (ret != ATCA_SUCCESS) {
    AWS_PRINTF("ERROR: SHA_MODE_SHA256_START @%d %d\n",
      __LINE__, (int)ret);
    return ret;
  }

  ret = atcab_hw_sha2_256_update(&sha256_ctx, m_hmac_key, 32);
  if (ret != ATCA_SUCCESS) {
    AWS_PRINTF("ERROR: SHA_MODE_SHA256_UPDATE @%d %d\n",
      __LINE__, (int)ret);
    return ret;
  }
  ret = atcab_hw_sha2_256_update(&sha256_ctx, pad, 32);
  if (ret != ATCA_SUCCESS) {
    AWS_PRINTF("ERROR: SHA_MODE_SHA256_UPDATE @%d %d\n",
      __LINE__, (int)ret);
    return ret;
  }

  sha256_init = true;

  return ATCA_SUCCESS;
}

ATCA_STATUS AtCryptoAuthLib::hmac_update(const uint8_t* data, size_t data_size)
{
  if (!sha256_init)
    return ATCA_BAD_PARAM;

  return atcab_hw_sha2_256_update(&sha256_ctx, data, data_size);
}

ATCA_STATUS AtCryptoAuthLib::hmac_finish(uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE])
{
  ATCA_STATUS ret;
  uint8_t pad[96];
  int i;

  if (!sha256_init) {
    return ATCA_BAD_PARAM;
  }
  sha256_init = false;

  memset(pad, 0x5c, 64);
  for (i = 0; i < 32; i++)
    pad[i] = m_hmac_key[i] ^ (0x5c ^ 0x36);

  ret = atcab_hw_sha2_256_finish(&sha256_ctx, &(pad[64]));
  if (ret != ATCA_SUCCESS) {
    AWS_PRINTF("ERROR: AtCryptoAuthLib::hmac_finish @%d %d\n",
      __LINE__, (int)ret);
    return ret;
  }
  memset(&sha256_ctx, 0, sizeof(sha256_ctx));
  memset(m_hmac_key, 0, 32);

  return atcab_hw_sha2_256(pad, 96, digest);
}

ATCA_STATUS AtCryptoAuthLib::ecdh_gen_key(uint8_t key[64])
{
  return gen_key(ECDHE_PRIV, key);
}

ATCA_STATUS AtCryptoAuthLib::ecdh(const uint8_t other_key[64], uint8_t pmk[32], SlotCfg sl)
{
// Send the encrypted version of the ECDH command with the public key provided
//if ((status = atcab_ecdh_enc(slotid, pubkey, pmk, encKey, enckeyid)) != ATCA_SUCCESS) BREAK(status, "ECDH Failed");
// ^^^ use this version instead

  return atcab_ecdh_enc((uint8_t)sl, other_key, pmk, m_enc_key, ENC_PARENT);
//  return atcab_ecdh((uint8_t)sl, other_key, pmk);
}

//uint8_t AtCryptoAuthLib::m_enc_key[ATCA_KEY_SIZE] = {0};

const uint8_t AtCryptoAuthLib::ENC_KEY[ATCA_KEY_SIZE] = {
  0xF9, 0x47, 0x2C, 0xBD, 0x33, 0x1D, 0x51, 0x00,
  0x0C, 0x45, 0x36, 0x34, 0x81, 0x37, 0x2F, 0xD8,
  0x5D, 0x5F, 0xB4, 0xB7, 0x25, 0x21, 0xF8, 0x90,
  0x52, 0xFA, 0xFC, 0x41, 0x02, 0x40, 0xE6, 0xF5,
};

ATCA_STATUS AtCryptoAuthLib::set_enc_key(const uint8_t* key)
{
  memcpy(m_enc_key, key, ATCA_KEY_SIZE);
  return ATCA_SUCCESS;
}

ATCA_STATUS AtCryptoAuthLib::atca_tls_init_enc_key()
{
  ATCA_STATUS ret = ATCA_SUCCESS;

  do {
//    ret = atcatls_set_enckey((uint8_t*)m_enc_key, ENC_PARENT, false);
//    if (ret != ATCA_SUCCESS) { break; }

    ret = atcatlsfn_set_get_enckey(atca_tls_set_enc_key, this);
    if (ret != ATCA_SUCCESS) { break; }

  } while(0);

  return ret;
}

ATCA_STATUS AtCryptoAuthLib::atca_tls_set_enc_key(uint8_t* outKey, int16_t keysize, void *ctx)
{
  AtCryptoAuthLib *lib = static_cast<AtCryptoAuthLib*>(ctx);
  ATCA_STATUS ret = ATCA_SUCCESS;

  do {

    if (outKey == NULL || keysize != ATCA_KEY_SIZE || lib == NULL) { break; }

    memcpy(outKey, lib->m_enc_key, keysize);

  } while(0);

  return ret;
}

size_t AtCryptoAuthLib::slot_size(SlotCfg slot)
{
  switch (slot) {
    case ENC_STORE:
      return 416;
    case ENC_STORE_9:
    case AUTH_CERT:
    case SIGNER_PUBKEY:
    case SIGNER_CERT:
    case FEATURE_CERT:
    case PKICA_PUBKEY:
    case AUTH_CERT_DATA:
      return 72;
    case ECDH_PMK:
    case ENC_PARENT:
      return 36;
    default:
      break;
  }
  return 0;
}

bool AtCryptoAuthLib::slot_encrypted(SlotCfg slot)
{
  switch (slot) {
    case ENC_STORE:
    case ENC_STORE_9:
    case ECDH_PMK:
      return true;
    default:
      break;
  }
  return false;
}

ATCA_STATUS AtCryptoAuthLib::read_slot(SlotCfg slot, uint8_t *data, size_t offs, size_t len)
{
  ATCA_STATUS ret = ATCA_SUCCESS;
  uint8_t dataout[32] = { 0 };
  uint8_t block;
  size_t i;
  size_t dptr;

  if ((len + offs) > slot_size(slot)) {
    return ATCA_BAD_PARAM;
  }
  block = offs/32;
  i = offs % 32;
  dptr = 0;
/*
  if (slot_encrypted(slot)) {
    ret = atcab_write_zone(ATCA_ZONE_DATA, ENC_PARENT, 0, 0, m_enc_key, ATCA_BLOCK_SIZE);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcatls_set_enckey %d\n", ret);
      return ret;;
    }
  }
*/
  memset(data, 0, len);
  while (dptr < len) {
    if (slot_encrypted(slot)) {
      ret = atcab_read_enc(slot, block, dataout, m_enc_key, ENC_PARENT);
    } else {
      ret = atcab_read_zone(ATCA_ZONE_DATA, slot, block, 0, dataout, 32);
    }
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcab_read %d\n", ret);
      break;
    }
    for ( ; (i < 32) && (dptr < len); i++) {
      data[dptr++] = dataout[i];
    }
    i = 0;
    block++;
  }
  memset(dataout, 0, 32);
  return ret;
}

ATCA_STATUS AtCryptoAuthLib::write_slot(SlotCfg slot, uint8_t *data, size_t offs, size_t len)
{
  ATCA_STATUS ret = ATCA_SUCCESS;
  uint8_t dataout[32] = { 0 };
  uint8_t block;
  size_t i;
  size_t dptr;

  if ((len + offs) > slot_size(slot)) {
    return ATCA_BAD_PARAM;
  }
  block = offs/32;
  i = offs % 32;
  dptr = 0;

  while (dptr < len) {
    if ((i == 0) && ((len-dptr) > 32)) {
      // write entire block
      memcpy(dataout, &(data[dptr]), 32);
      dptr += 32;
    } else {
      // read-modify-write
      if (slot_encrypted(slot)) {
        ret = atcab_read_enc(slot, block, dataout, m_enc_key, ENC_PARENT);
      } else {
        ret = atcab_read_zone(ATCA_ZONE_DATA, slot, block, 0, dataout, 32);
      }
      if (ret != ATCA_SUCCESS) {
        AWS_PRINTF("ERROR: atcab_read %d\n", ret);
        break;
      }
      for ( ; (i < 32) && (dptr < len); i++) {
        dataout[i] = data[dptr++];
      }
      i = 0;
    }
    if (slot_encrypted(slot)) {
      ret = atcab_write_enc(slot, block, dataout, m_enc_key, ENC_PARENT);
    } else {
      ret = atcab_write_zone(ATCA_ZONE_DATA, slot, block, 0, dataout, 32);
    }
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcab_write %d\n", ret);
      break;
    }
    block++;
  }
  memset(dataout, 0, 32);
  return ret;
}

bool AtCryptoAuthLib::verify_cert_chain(uint8_t *caPubKey,
  uint8_t *signerCert, size_t *signerCertSize,
  uint8_t *deviceCert, size_t *deviceCertSize)
{
  ATCA_STATUS status = ATCA_GEN_FAIL;
  uint8_t signerPubkey[64] = { 0 };

  do {
    // Get the signer certificate - ATCACERT_E_WRONG_CERT_DEF
    status = atcatls_get_cert(&my_signer_cert_def, caPubKey, signerCert, signerCertSize);
    if (status == ATCACERT_E_WRONG_CERT_DEF) {
      AWS_PRINTF("ERROR: atcatls_get_cert signer Wrong Cert Def\n");
    } else if (status != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcatls_get_cert signer %x\n", status);
      break;
    }

    // Verify the signer certificate
    status = (ATCA_STATUS)atcacert_verify_cert_hw(&my_signer_cert_def, signerCert, *signerCertSize, caPubKey);
    if (status != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcacert_verify_cert_hw signer %d\n", status);
      break;
    }

    // Get the signer public key from the signer certificate
    status = (ATCA_STATUS)atcacert_get_subj_public_key(&my_signer_cert_def, signerCert, *signerCertSize, signerPubkey);
    if (status != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcacert_get_subj_public_key %d\n", status);
      break;
    }

    // Get the device certificate
    status = atcatls_get_cert(&my_device_cert_def, signerPubkey, deviceCert, deviceCertSize);
    if (status == ATCACERT_E_WRONG_CERT_DEF) {
      AWS_PRINTF("ERROR: atcatls_get_cert device Wrong Cert Def\n");
    } else if (status != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcatls_get_cert device %d\n", status);
      break;
    }

    // Verify the device certificate
    status = (ATCA_STATUS)atcacert_verify_cert_hw(&my_device_cert_def, deviceCert, *deviceCertSize, signerPubkey);
    if (status != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcacert_verify_cert_hw device %d\n", status);
      break;
    }
  } while (0);

  if (status == ATCA_SUCCESS) {
    AWS_PRINTF("Verify Cert PASS %d\n", __LINE__);
    return true;
  } else {
    AWS_PRINTF("Verify Cert FAIL %d\n", __LINE__);
    return false;
  }
}

// modified W25 ECC508 configuration
//   (slot 7 has external sign turned on for cert testing)
const uint8_t AtCryptoAuthLib::golden_ecc_configdata[ATCA_CONFIG_SIZE] = {
  // block 0
  // Not Written: First 16 bytes are not written
  0x01, 0x23, 0x00, 0x00, // SN
  0x00, 0x00, 0x50, 0x00, // rev num
  0x04, 0x05, 0x06, 0x07, // SN
  0xEE, 0x00, 0x01, 0x00, // SN, I2C en
  // I2C, reserved, OtpMode, ChipMode
  0xC0, 0x00, 0x55, 0x00,
  // SlotConfig
  0x87, 0x20, // slot 0 - TLS_SLOT_AUTH_PRIV      (0)
  0x87, 0x20, // slot 0 - TLS_SLOT_AUTH_PRIV      (1)
  0x8F, 0x20, // slot 2 - TLS_SLOT_ECDHE_PRIV     (2)
  0xC4, 0x44, // slot 3 - TLS_SLOT_ECDH_PMK       (3)
  0x8F, 0x0F, // slot 4 - TLS_SLOT_ENC_PARENT     (4)
  0x83, 0x64, // slot 7 - TLS_SLOT_FEATURE_PRIV   (5)
  0x83, 0x64, // slot 7 - TLS_SLOT_FEATURE_PRIV   (6)
  0x83, 0x64, // slot 7 - TLS_SLOT_FEATURE_PRIV   (7)
  0xC4, 0x44, // slot 8 - TLS_SLOT8_ENC_STORE     (8) Size = 384
  0xC4, 0x44, // slot 9 - TLS_SLOT9_ENC_STORE     (9) Size = 64
  0x0F, 0x0F, // slot 10 - TLS_SLOT_AUTH_CERT     (A) Compressed certificate
  0x0F, 0x0F, // slot 11 - TLS_SLOT_SIGNER_PUBKEY (B)
  0x0F, 0x0F, // slot 12 - TLS_SLOT_SIGNER_CERT   (C) Compressed certificate
  0x0F, 0x0F, // slot 13 - TLS_SLOT_FEATURE_CERT  (D) Compressed certificate
  0x0F, 0x0F, // slot 14 - TLS_SLOT_PKICA_PUBKEY  (E)
  0x0F, 0x0F, // slot 15 - TLS_SLOT_DEVICE_CERT   (F)
  // Counters
  0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00,
  // Last Key Use
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF,
  // Not Written: UserExtra, Selector, LockValue, LockConfig (word offset = 5)
  0x00, 0x00, 0x00, 0x00,
// -- end of common sha204 data -- (88 bytes)
  // SlotLock[2], RFU[2]
  0xFF, 0xFF, 0x00, 0x00,
  // X.509 Format
  0x00, 0x00, 0x00, 0x00,
  // KeyConfig
  0x13, 0x00, // slot 0 - TLS_SLOT_AUTH_PRIV      (0)
  0x13, 0x00, // slot 0 - TLS_SLOT_AUTH_PRIV      (1)
  0x33, 0x00, // slot 2 - TLS_SLOT_ECDHE_PRIV     (2)
  0x1C, 0x00, // slot 3 - TLS_SLOT_ECDH_PMK       (3)
  0x3C, 0x00, // slot 4 - TLS_SLOT_ENC_PARENT     (4)
  0x33, 0x00, // slot 7 - TLS_SLOT_FEATURE_PRIV   (5)
  0x33, 0x00, // slot 7 - TLS_SLOT_FEATURE_PRIV   (6)
  0x33, 0x00, // slot 7 - TLS_SLOT_FEATURE_PRIV   (7)
  0x1C, 0x00, // slot 8 - TLS_SLOT8_ENC_STORE     (8)
  0x1C, 0x00, // slot 9 - TLS_SLOT9_ENC_STORE     (9)
  0x3C, 0x00, // slot 10 - TLS_SLOT_AUTH_CERT     (A)
  0x3C, 0x00, // slot 11 - TLS_SLOT_SIGNER_PUBKEY (B)
  0x3C, 0x00, // slot 12 - TLS_SLOT_SIGNER_CERT   (C)
  0x3C, 0x00, // slot 13 - TLS_SLOT_FEATURE_CERT  (D)
  0x3C, 0x00, // slot 14 - TLS_SLOT_PKICA_PUBKEY  (E)
  0x3C, 0x00, // slot 15 - TLS_SLOT_DEVICE_CERT   (F)
};
/* Config notes
only slot 7 allows priv_write
only slot 0 writes encrypted ECDH to slot+1

TODO:
  0 <- 2
  1 <- 0
  2 <- 1
  3,5,6 <- 7

*/

ATCA_STATUS AtCryptoAuthLib::config_locked(bool &lockstate)
{
  ATCA_STATUS ret = ATCA_SUCCESS;
  bool ls = 0;

  do {
    ret = atcab_is_locked(LOCK_ZONE_CONFIG, &ls);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcab_is_locked(LOCK_ZONE_CONFIG %d\n", ret);
      break;
    }
    lockstate = ls;
  } while (0);

  return ret;
}

ATCA_STATUS AtCryptoAuthLib::check_config(bool &match)
{
  ATCA_STATUS ret = ATCA_SUCCESS;
  uint8_t configdata[ATCA_CONFIG_SIZE] = { 0 };
  bool lock;

  match = false;
  do {
    ret = config_locked(lock);
    if ((ret != ATCA_SUCCESS) || !lock) {
      break;
    }
    ret = atcab_read_ecc_config_zone((uint8_t*)configdata);
    if (ret != ATCA_SUCCESS) {
      break;
    }
    if (memcmp(&(configdata[20]), &(golden_ecc_configdata[20]), ATCA_CONFIG_SIZE-20) == 0) {
      match = true;
    }
  } while (0);

  return ret;
}

ATCA_STATUS AtCryptoAuthLib::config_chip(const uint8_t *access_key)
{
  ATCA_STATUS ret = ATCA_SUCCESS;
  bool lockstate = 0;
  uint8_t lock_response;
  uint8_t configdata[ATCA_CONFIG_SIZE] = { 0 };

  if (access_key != NULL)
    set_enc_key(access_key);

  do {
    // Check the lock state of the config zone.  If unlocked, then write and lock.
    ret = atcab_is_locked(LOCK_ZONE_CONFIG, &lockstate);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcab_is_locked(LOCK_ZONE_CONFIG %d\n", ret);
      break;
    }
    if (!lockstate) {
      ret = atcab_write_ecc_config_zone(golden_ecc_configdata);
      if (ret != ATCA_SUCCESS) {
        AWS_PRINTF("ERROR: atcab_write_ecc_config_zone %d\n", ret);
        break;
      }

      ret = atcab_lock_config_zone(&lock_response);
      if (ret != ATCA_SUCCESS) {
        AWS_PRINTF("ERROR: atcab_lock_config_zone %d\n", ret);
        break;
      }
    } else {
      AWS_PRINTF("Already Locked\n");
    }
    // Refresh the configuration zone data with the bytes that are now on the device
    ret = atcab_read_ecc_config_zone((uint8_t*)&configdata);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcab_read_ecc_config_zone %d\n", ret);
      break;
    }

    // Check the Data zone lock
    ret = atcab_is_locked(LOCK_ZONE_DATA, &lockstate);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcab_is_locked(LOCK_ZONE_DATA %d\n", ret);
      break;
    }
    if (!lockstate) {
      uint8_t pubKey[64];

      ret = atcab_write_zone(DEVZONE_DATA, ENC_PARENT, 0, 0, m_enc_key, 32);
      if (ret != ATCA_SUCCESS) {
        AWS_PRINTF("ERROR: atcab_write_zone(DEVZONE_DATA %d\n", ret);
        break;
      }

      ret = atcab_genkey((uint16_t)AUTH_PRIV, pubKey);
      if (ret != ATCA_SUCCESS) {
        AWS_PRINTF("ERROR: atcab_genkey AUTH_PRIV %d\n", ret);
        break;
      }

      ret = atcab_lock_data_zone(&lock_response);
      if (ret != ATCA_SUCCESS) {
        AWS_PRINTF("ERROR: atcab_lock_data_zone %d\n", ret);
        break;
      }
    }

  } while (0);

  return ret;
}

/*
extern "C"
void atca_delay_ms(uint32_t d)
{
  delay(d);
}
*/

// ** Provision With Device Stored Certs **

#include "atcacert/atcacert_def.h"
#include "atcacert/atcacert_client.h"

#define CERT_DEF_DEVICE (&my_device_cert_def)
#define CERT_DEF_SIGNER (&my_signer_cert_def)

#define AWS_CERT_LENGH_MAX					(1024)

#define AWS_ROOT_CERT_ID    (uint8_t)(0x00)  // Root Cert Identifier
#define AWS_SIGNER_CERT_ID  (uint8_t)(0x01)  // Signer Cert Identifier
#define AWS_VERIF_CERT_ID   (uint8_t)(0x02)  // Verification Cert Identifier
#define AWS_DEVICE_CERT_ID  (uint8_t)(0x03)  // Device Cert Identifier


int AtCryptoAuthLib::provision_load_signer_cert(
  const char               *pem_cert,
  size_t                    pem_cert_len,
  uint8_t                  *tbs_data, // ATCA_SHA_DIGEST_SIZE
  uint8_t                   signer_id[2],
  const atcacert_tm_utc_t  *issue_date)
{
  int ret = ATCA_SUCCESS;
  uint8_t der_cert[AWS_CERT_LENGH_MAX];
  size_t der_cert_len;
  uint8_t signer_pub_key[ATCA_PUB_KEY_SIZE] = { 0 };

  do {
    der_cert_len = AWS_CERT_LENGH_MAX;
    ret = atcacert_decode_pem_cert(pem_cert, pem_cert_len,
            der_cert, &der_cert_len);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcatls_random %d\n", ret);
      break;
    }
AWS_PRINTF("provision_load_signer_cert %d\n", __LINE__);

    ret = atcacert_get_subj_public_key(CERT_DEF_SIGNER,
            der_cert, der_cert_len, signer_pub_key);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcacert_get_subj_public_key %d\n", ret);
      break;
    }
AWS_PRINTF("provision_load_signer_cert %d\n", __LINE__);

    ret = atcacert_get_signer_id(CERT_DEF_SIGNER,
            der_cert, der_cert_len, signer_id);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: atcacert_get_signer_id %d\n", ret);
      break;
    }
AWS_PRINTF("provision_load_signer_cert %d\n", __LINE__);

    ret = aws_prov_save_cert(AWS_SIGNER_CERT_ID, pem_cert, pem_cert_len);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: aws_prov_save_cert %d\n", ret);
      break;
    }
AWS_PRINTF("provision_load_signer_cert %d\n", __LINE__);

    ret = aws_prov_save_signer_public_key(signer_pub_key);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: aws_prov_save_signer_public_key %d\n", ret);
      break;
    }
AWS_PRINTF("provision_load_signer_cert %d\n", __LINE__);

    ret = aws_prov_build_device_tbs(tbs_data, signer_pub_key, signer_id, issue_date);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: aws_prov_build_device_tbs %d\n", ret);
      break;
    }
AWS_PRINTF("provision_load_signer_cert %d\n", __LINE__);

  } while(0);

  return ret;
}

uint8_t AtCryptoAuthLib::aws_prov_save_cert( uint8_t cert_id, const char *cert_pem,
                            size_t cert_pem_len)
{
  uint8_t status = ATCA_SUCCESS;
  const atcacert_def_t* cert_def;
  uint8_t der_cert[AWS_CERT_LENGH_MAX];
  size_t der_cert_size = sizeof(der_cert);
  char* start_pem = NULL;
  char* end_pem = NULL;
  uint16_t buffer_length = 0;

  do {
    if (cert_id == AWS_SIGNER_CERT_ID)
      cert_def = CERT_DEF_SIGNER;
    else if (cert_id == AWS_DEVICE_CERT_ID)
      cert_def = CERT_DEF_DEVICE;
    else
      break;

    start_pem = strstr(cert_pem, PEM_CERT_BEGIN);
    end_pem = strstr(cert_pem, PEM_CERT_END);
    buffer_length = end_pem - start_pem + sizeof(PEM_CERT_END) + 1;

    status = atcacert_decode_pem_cert((const char*)start_pem, buffer_length, der_cert, &der_cert_size);
    if (status != ATCA_SUCCESS)
      break;

    status = atcacert_write_cert(cert_def, der_cert, der_cert_size);
    if (status != ATCA_SUCCESS)
      break;

  } while (0);
  
  return status;
}

uint8_t AtCryptoAuthLib::aws_prov_save_signer_public_key(const uint8_t* public_key)
{
  uint8_t ret = ATCA_SUCCESS;
  size_t end_block = 3, start_block = 0;
  uint8_t padded_public_key[96];

  memset(padded_public_key, 0x00, sizeof(padded_public_key));
  memmove(&padded_public_key[40], &public_key[32], 32);
  memset(&padded_public_key[36], 0, 4);
  memmove(&padded_public_key[4], &public_key[0], 32);
  memset(&padded_public_key[0], 0, 4);

  for (; start_block < end_block; start_block++) {
    ret = atcab_write_zone(DEVZONE_DATA, SIGNER_PUBKEY, 
              start_block, 0, &padded_public_key[(start_block - 0) * 32], 32);
    if (ret != ATCA_SUCCESS) return ret;
  }

  return ret;
}

uint8_t AtCryptoAuthLib::aws_prov_build_device_tbs(
  uint8_t                 *tbs_digest,
  const uint8_t            signer_public_key[64],
  const uint8_t            signer_id[2],
  const atcacert_tm_utc_t* issue_date)
{
  uint8_t status = ATCA_SUCCESS;
  bool lockstate = false;
  uint8_t device_public_key[ATCA_PUB_KEY_SIZE] = { 0 };
  uint8_t device_cert[AWS_CERT_LENGH_MAX];
  size_t  device_cert_size = sizeof(device_cert);
  uint8_t configdata[ATCA_CONFIG_SIZE];

  do {
    status = atcab_is_locked(LOCK_ZONE_CONFIG, &lockstate);
    if (status != ATCA_SUCCESS || !lockstate) break;

    status = atcab_read_config_zone(configdata);
    if (status != ATCA_SUCCESS) break;

    status = atcab_genkey(AUTH_PRIV, device_public_key);
    if (status != ATCA_SUCCESS) break;

    status = atcab_get_pubkey(AUTH_PRIV, device_public_key);
    if (status != ATCA_SUCCESS) break;

    status = aws_prov_build_tbs_cert_digest(CERT_DEF_DEVICE, device_cert, &device_cert_size, signer_public_key,
        device_public_key, signer_id, issue_date, configdata, tbs_digest);
    if (status != ATCA_SUCCESS) break;

    status = aws_prov_save_signer_public_key(signer_public_key);
    if (status != ATCA_SUCCESS) break;

  } while(0);

  return status;
}

uint8_t AtCryptoAuthLib::aws_prov_build_tbs_cert_digest(
  const atcacert_def_t*    cert_def,
  uint8_t*                 cert,
  size_t*                  cert_size,
  const uint8_t            ca_public_key[64],
  const uint8_t            public_key[64],
  const uint8_t            signer_id[2],
  const atcacert_tm_utc_t* issue_date,
  const uint8_t            config32[32],
  uint8_t*                 tbs_digest)
{
  int ret = ATCACERT_E_SUCCESS;
  uint8_t key_id[20];
  atcacert_build_state_t build_state;

  atcacert_tm_utc_t expire_date;
  expire_date.tm_year = issue_date->tm_year + cert_def->expire_years;
  expire_date.tm_mon = issue_date->tm_mon;
  expire_date.tm_mday = issue_date->tm_mday;
  expire_date.tm_hour = issue_date->tm_hour;
  expire_date.tm_min = 0;
  expire_date.tm_sec = 0;

  atcacert_device_loc_t config32_dev_loc;
  config32_dev_loc.zone = DEVZONE_CONFIG;
  config32_dev_loc.offset = 0;
  config32_dev_loc.count = 32;

  if (cert_def->expire_years == 0)
  {
    ret = atcacert_date_get_max_date(cert_def->expire_date_format, &expire_date);
    if (ret != ATCACERT_E_SUCCESS) return ret;
  }

  ret = atcacert_get_key_id(ca_public_key, key_id);
  if (ret != ATCACERT_E_SUCCESS) return ret;

  ret = atcacert_cert_build_start(&build_state, cert_def, cert, cert_size, ca_public_key);
  if (ret != ATCACERT_E_SUCCESS) return ret;

  ret = atcacert_set_subj_public_key(build_state.cert_def, build_state.cert, *build_state.cert_size, public_key);
  if (ret != ATCACERT_E_SUCCESS) return ret;
  ret = atcacert_set_issue_date(build_state.cert_def, build_state.cert, *build_state.cert_size, issue_date);
  if (ret != ATCACERT_E_SUCCESS) return ret;
  ret = atcacert_set_expire_date(build_state.cert_def, build_state.cert, *build_state.cert_size, &expire_date);
  if (ret != ATCACERT_E_SUCCESS) return ret;

  ret = atcacert_set_signer_id(build_state.cert_def, build_state.cert, *build_state.cert_size, signer_id);
  if (ret != ATCACERT_E_SUCCESS) return ret;
  ret = atcacert_cert_build_process(&build_state, &config32_dev_loc, config32);
  if (ret != ATCACERT_E_SUCCESS) return ret;

  ret = atcacert_cert_build_finish(&build_state);
  if (ret != ATCACERT_E_SUCCESS) return ret;

  ret = atcacert_get_tbs_digest(build_state.cert_def, build_state.cert, *build_state.cert_size, tbs_digest);
  if (ret != ATCACERT_E_SUCCESS) return ret;

  return ret;
}

int AtCryptoAuthLib::provision_save_signature(
  const uint8_t             cert_signature[ATCA_SIG_SIZE],
  const uint8_t             signer_id[2],
  const atcacert_tm_utc_t  *issue_date)
{
  int ret = ATCA_SUCCESS;

  do {
    ret = aws_prov_save_signature(AWS_DEVICE_CERT_ID, cert_signature,
            signer_id, issue_date);
    if (ret != ATCA_SUCCESS) {
      AWS_PRINTF("ERROR: aws_prov_save_signature %d\n", ret);
      break;
    }
  } while(0);

  return ret;
}

uint8_t AtCryptoAuthLib::aws_prov_save_signature(
  uint8_t                   cert_id,
  const uint8_t             cert_signature[ATCA_SIG_SIZE],
  const uint8_t             signer_id[2],
  const atcacert_tm_utc_t  *issue_date)
{
  uint8_t status = ATCA_SUCCESS;

  do {
    if (cert_id != AWS_SIGNER_CERT_ID && cert_id != AWS_DEVICE_CERT_ID)
      break;

    status = aws_prov_build_and_save_cert(cert_signature, cert_id,
                signer_id, issue_date);
    if (status != ATCA_SUCCESS)
      break;

  } while (0);
  
  return status;
}

uint8_t AtCryptoAuthLib::aws_prov_build_and_save_cert(
  const uint8_t* signature, uint8_t cert_id,
  const uint8_t signer_id[2],
  const atcacert_tm_utc_t *issue_date)
{
  uint8_t ret = ATCA_SUCCESS;
  uint8_t cert[AWS_CERT_LENGH_MAX] = {0}, tbs_digest[ATCA_SHA_DIGEST_SIZE];
  const atcacert_def_t* cert_def = (cert_id == AWS_SIGNER_CERT_ID) ? CERT_DEF_SIGNER : CERT_DEF_DEVICE;
  size_t cert_size = sizeof(cert);
  size_t max_cert_size = cert_size;
  uint8_t pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
  uint8_t signer_pub_key[ATCA_PUB_KEY_SIZE] = { 0 };
  uint8_t configdata[ATCA_CONFIG_SIZE];
  atcacert_device_loc_t device_locs[4];
  size_t device_locs_count = 0;
  size_t i;
  
  do {
    ret = atcab_read_config_zone(configdata);
    if (ret != ATCA_SUCCESS) break;
    
    ret = atcab_get_pubkey(AUTH_PRIV, pub_key);
    if (ret != ATCA_SUCCESS) break;

    ret = aws_prov_get_signer_public_key(signer_pub_key);
    if (ret != ATCA_SUCCESS) break;

    ret = aws_prov_build_tbs_cert_digest(cert_def, cert, &cert_size, signer_pub_key, 
        pub_key, signer_id, issue_date, configdata, tbs_digest);
    if (ret != ATCACERT_E_SUCCESS) break;

    ret = atcacert_set_signature(cert_def, cert, &cert_size, max_cert_size, signature);
    if (ret != ATCACERT_E_SUCCESS) return ret;

    ret = atcacert_get_device_locs(cert_def, device_locs, &device_locs_count,
            sizeof(device_locs) / sizeof(device_locs[0]), 32);
    if (ret != ATCACERT_E_SUCCESS) return ret;

    for (i = 0; i < device_locs_count; i++)  {

      size_t end_block, start_block, block;
      uint8_t data[96];

      if (device_locs[i].zone == DEVZONE_CONFIG)
        continue;
      if (device_locs[i].zone == DEVZONE_DATA && device_locs[i].is_genkey)
        continue;

      ret = atcacert_get_device_data(cert_def, cert, cert_size, &device_locs[i], data);
      if (ret != ATCACERT_E_SUCCESS) return ret;

      start_block = device_locs[i].offset / 32;
      end_block = (device_locs[i].offset + device_locs[i].count) / 32;
      for (block = start_block; block < end_block; block++) {
        ret = atcab_write_zone(device_locs[i].zone, device_locs[i].slot,
                (uint8_t)block, 0, &data[(block - start_block) * 32], 32);
        if (ret != ATCA_SUCCESS) return ret;
      }
    }    
  } while (0);

  return ret;
}

uint8_t AtCryptoAuthLib::aws_prov_get_signer_public_key(uint8_t* public_key)
{
  uint8_t ret = ATCA_SUCCESS;
  size_t end_block = 3, start_block = 0;
  uint8_t padded_public_key[96];

  memset(padded_public_key, 0x00, sizeof(padded_public_key));
  for (; start_block < end_block; start_block++) {
    ret = atcab_read_zone(DEVZONE_DATA, SIGNER_PUBKEY, 
              start_block, 0, &padded_public_key[(start_block - 0) * 32], 32);
    if (ret != ATCA_SUCCESS) return ret;
  }

  memcpy(&public_key[32], &padded_public_key[40], 32);
  memcpy(&public_key[0], &padded_public_key[4], 32);

  return ret;
}

uint8_t g_signer_pubkey[64];

int AtCryptoAuthLib::build_signer_cert(uint8_t *signer_der,
  size_t *signer_der_size, uint8_t *signer_pem, size_t *signer_pem_size)
{
	int ret = ATCACERT_E_SUCCESS;

	do {

		if (signer_der == NULL || signer_pem == NULL) {
      AWS_PRINTF("atca_tls_build_signer_cert: Failed: invalid param\n");
      break;
    }

		ret = atcatls_get_cert(&my_signer_cert_def, NULL, signer_der, signer_der_size);
		if (ret != ATCACERT_E_SUCCESS) {
      AWS_PRINTF("Failed: read signer certificate %d\n", ret);
      break;
    }

		ret = atcacert_encode_pem_cert(signer_der, *signer_der_size, (char*)signer_pem, signer_pem_size);
		if (signer_pem_size <= 0) {
      AWS_PRINTF("Failed: convert signer certificate %d\n", ret);
      break;
    }

		ret = atcacert_get_subj_public_key(&my_signer_cert_def, signer_der, *signer_der_size, g_signer_pubkey);
		if (ret != ATCACERT_E_SUCCESS) {
      AWS_PRINTF("Failed: read signer public key %d\n", ret);
      break;
    }

	} while(0);

	return ret;
}

/**
 * \brief Build device certificate.
 */
int AtCryptoAuthLib::build_device_cert(uint8_t *device_der,
  size_t *device_der_size, uint8_t *device_pem, size_t *device_pem_size)
{
  uint8_t device_pubkey[64];
	int ret = ATCA_SUCCESS;

// read signer pub key

	do {

		if (device_der == NULL || device_pem == NULL) {
      AWS_PRINTF("Failed: invalid param");
      break;
    }

		ret = atcatls_get_cert(&my_device_cert_def, g_signer_pubkey, device_der, device_der_size);
		if (ret != ATCACERT_E_SUCCESS) {
      AWS_PRINTF("Failed: read device certificate %d\n", ret);
      break;
    }

		ret = atcacert_encode_pem_cert(device_der, *device_der_size, (char*)device_pem, device_pem_size);
		if (device_pem_size <= 0) {
      AWS_PRINTF("Failed: convert device certificate %d\n", ret);
      break;
    }

		ret = atcacert_get_subj_public_key(&my_device_cert_def, device_der, *device_der_size, device_pubkey);
		if (ret != ATCACERT_E_SUCCESS) {
      AWS_PRINTF("Failed: read device public key %d\n", ret);
      break;
    }

	} while(0);
	
	return ret;
}




