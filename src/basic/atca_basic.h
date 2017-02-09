/**
 * \file
 * \brief CryptoAuthLib Basic API methods - a simple crypto authentication api.
 * These methods manage a global ATCADevice object behind the scenes.  They also
 * manage the wake/idle state transitions so callers don't need to.
 *
 * \copyright Copyright (c) 2015 Atmel Corporation. All rights reserved.
 *
 * \atmel_crypto_device_library_license_start
 *
 * \page License
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel integrated circuit.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \atmel_crypto_device_library_license_stop
 */

#include "cryptoauthlib.h"
#include "crypto/atca_crypto_sw_sha2.h"

#ifndef ATCA_BASIC_H_
#define ATCA_BASIC_H_

#define TBD   void

/** \defgroup atcab_ Basic Crypto API methods (atcab_)
 *
 * \brief
 * These methods provide the most convenient, simple API to CryptoAuth chips
 *
   @{ */

#ifdef __cplusplus
extern "C" {
#endif

// basic global device object methods
ATCA_STATUS atcab_version( char *verstr );
ATCA_STATUS atcab_init(ATCAIfaceCfg *cfg);
ATCA_STATUS atcab_init_device(ATCADevice cadevice);
ATCA_STATUS atcab_release(void);
ATCADevice atcab_getDevice(void);

ATCA_STATUS atcab_wakeup(void);
ATCA_STATUS atcab_idle(void);
ATCA_STATUS atcab_sleep(void);

// discovery
ATCA_STATUS atcab_cfg_discover( ATCAIfaceCfg cfgArray[], int max);

// basic crypto API
ATCA_STATUS atcab_info(uint8_t *revision);
ATCA_STATUS atcab_challenge(const uint8_t *challenge);
ATCA_STATUS atcab_challenge_seed_update(const uint8_t *seed, uint8_t* rand_out);
ATCA_STATUS atcab_nonce_base(uint8_t mode, const uint8_t *num_in, uint8_t* rand_out);
ATCA_STATUS atcab_nonce(const uint8_t *tempkey);
ATCA_STATUS atcab_nonce_rand(const uint8_t *seed, uint8_t* rand_out);
ATCA_STATUS atcab_random(uint8_t *rand_out);

ATCA_STATUS atcab_is_locked(uint8_t zone, bool *lock_state);
ATCA_STATUS atcab_is_slot_locked(uint8_t slot, bool *lock_state);

ATCA_STATUS atcab_get_addr(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint16_t* addr);
ATCA_STATUS atcab_get_zone_size(uint8_t zone, uint16_t slot, size_t* size);
ATCA_STATUS atcab_read_zone(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, uint8_t *data, uint8_t len);
ATCA_STATUS atcab_write(uint8_t zone, uint16_t address, const uint8_t *value, const uint8_t *mac);
ATCA_STATUS atcab_write_zone(uint8_t zone, uint16_t slot, uint8_t block, uint8_t offset, const uint8_t *data, uint8_t len);
ATCA_STATUS atcab_write_bytes_zone(uint8_t zone, uint16_t slot, size_t offset_bytes, const uint8_t *data, size_t length);
ATCA_STATUS atcab_read_bytes_zone(uint8_t zone, uint16_t slot, size_t offset_bytes, uint8_t *data, size_t length);

ATCA_STATUS atcab_read_serial_number(uint8_t* serial_number);
ATCA_STATUS atcab_read_pubkey(uint16_t slot8toF, uint8_t *pubkey);
ATCA_STATUS atcab_write_pubkey(uint16_t slot8toF, const uint8_t *pubkey);
ATCA_STATUS atcab_read_sig(uint8_t slot8toF, uint8_t *sig);
ATCA_STATUS atcab_read_ecc_config_zone(uint8_t* config_data);
ATCA_STATUS atcab_write_ecc_config_zone(const uint8_t* config_data);
ATCA_STATUS atcab_read_sha_config_zone( uint8_t* config_data);
ATCA_STATUS atcab_write_sha_config_zone(const uint8_t* config_data);
ATCA_STATUS atcab_read_config_zone(uint8_t* config_data);
ATCA_STATUS atcab_write_config_zone(const uint8_t* config_data);
ATCA_STATUS atcab_cmp_config_zone(uint8_t* config_data, bool* same_config);

ATCA_STATUS atcab_read_enc(uint16_t key_id, uint8_t block, uint8_t *data, const uint8_t* enckey, const uint16_t enckeyid);
ATCA_STATUS atcab_write_enc(uint16_t key_id, uint8_t block, const uint8_t *data, const uint8_t* enckey, const uint16_t enckeyid);

ATCA_STATUS atcab_lock(uint8_t mode, uint16_t summary, uint8_t* lock_response);
ATCA_STATUS atcab_lock_config_zone(uint8_t* lock_response);
ATCA_STATUS atcab_lock_config_zone_crc(uint16_t crc);
ATCA_STATUS atcab_lock_data_zone(uint8_t* lock_response);
ATCA_STATUS atcab_lock_data_zone_crc(uint16_t crc);
ATCA_STATUS atcab_lock_data_slot(uint8_t slot, uint8_t* lock_response);

ATCA_STATUS atcab_priv_write(uint16_t key_id, const uint8_t priv_key[36], uint8_t write_key_slot, const uint8_t write_key[32]);
ATCA_STATUS atcab_genkey_base(uint8_t mode, uint16_t key_id, const uint8_t* other_data, uint8_t* public_key);
ATCA_STATUS atcab_genkey(uint16_t key_id, uint8_t *public_key);
ATCA_STATUS atcab_get_pubkey(uint16_t key_id, uint8_t *public_key);
ATCA_STATUS atcab_sign_base(uint8_t mode, uint16_t key_id, uint8_t *signature);
ATCA_STATUS atcab_sign(uint16_t key_id, const uint8_t *msg, uint8_t *signature);
ATCA_STATUS atcab_sign_internal(uint16_t key_id, bool is_invalidate, bool is_full_sn, uint8_t *signature);
ATCA_STATUS atcab_verify(uint8_t mode, uint16_t key_id, const uint8_t* signature, const uint8_t* public_key, const uint8_t* other_data);
ATCA_STATUS atcab_verify_extern(const uint8_t *message, const uint8_t *signature, const uint8_t *public_key, bool *is_verified);
ATCA_STATUS atcab_verify_stored(const uint8_t *message, const uint8_t *signature, uint16_t key_id, bool *is_verified);
ATCA_STATUS atcab_verify_validate(uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified);
ATCA_STATUS atcab_verify_invalidate(uint16_t key_id, const uint8_t *signature, const uint8_t *other_data, bool *is_verified);
ATCA_STATUS atcab_ecdh(uint16_t key_id, const uint8_t* pubkey, uint8_t* pms);
ATCA_STATUS atcab_ecdh_enc(uint16_t key_id, const uint8_t* pubkey, uint8_t* pms, const uint8_t* enckey, uint16_t enckeyid);
ATCA_STATUS atcab_gendig(uint8_t zone, uint16_t key_id, const uint8_t *other_data, uint8_t other_data_size);
ATCA_STATUS atcab_mac( uint8_t mode, uint16_t key_id, const uint8_t* challenge, uint8_t* digest );
ATCA_STATUS atcab_checkmac( uint8_t mode, uint16_t key_id, const uint8_t *challenge, const uint8_t *response, const uint8_t *other_data);
ATCA_STATUS atcab_hmac(uint8_t mode, uint16_t key_id, uint8_t* digest);
ATCA_STATUS atcab_derivekey(uint8_t random, uint16_t key_id, uint8_t* mac);


ATCA_STATUS atcab_sha_base(uint8_t mode, uint16_t length, const uint8_t* message, uint8_t* digest);
ATCA_STATUS atcab_sha_start(void);
ATCA_STATUS atcab_sha_update(const uint8_t *message);
ATCA_STATUS atcab_sha_end(uint8_t *digest, uint16_t length, const uint8_t *message);
ATCA_STATUS atcab_sha(uint16_t length, const uint8_t *message, uint8_t *digest);

ATCA_STATUS atcab_updateextra(uint8_t mode, uint16_t new_value);

typedef struct atca_sha256_ctx {
	uint32_t total_msg_size;  //!< Total number of message bytes processed
	uint32_t block_size;      //!< Number of bytes in current block
	uint8_t block[64 * 2];    //!< Unprocessed message storage
	uint32_t hash[8];         //!< Hash state
} atca_sha256_ctx_t;

ATCA_STATUS atcab_hw_sha2_256_init(atca_sha256_ctx_t* ctx);
ATCA_STATUS atcab_hw_sha2_256_update(atca_sha256_ctx_t* ctx, const uint8_t* data, size_t data_size);
ATCA_STATUS atcab_hw_sha2_256_finish(atca_sha256_ctx_t * ctx, uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);
ATCA_STATUS atcab_hw_sha2_256(const uint8_t * data, size_t data_size, uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* ATCA_BASIC_H_ */