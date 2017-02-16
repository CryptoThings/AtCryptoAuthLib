
/**
 * Copyright (c) 2016-2017 Robert Totte
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <stddef.h>

#include "atca_command.h"
#include "tls/atcatls.h"

#ifndef __ATCRYPTOAUTHLIB_H__
#define __ATCRYPTOAUTHLIB_H__

// ATCA_STATUS

class AtCryptoAuthLib
{
  public:
    typedef enum e_slot_cfg {
      AUTH_PRIV      = 0x0,
      AUTH_PRIV_2    = 0x1,
      ECDHE_PRIV     = 0x2,
      ECDH_PMK       = 0x3,
      ENC_PARENT     = 0x4,
      ECC_KEY_1      = 0x5,
      ECC_KEY_2      = 0x6,
      ECC_KEY_3      = 0x7,
      ENC_STORE      = 0x8,
      ENC_STORE_9    = 0x9,
      AUTH_CERT      = 0xA,
      SIGNER_PUBKEY  = 0xB,
      SIGNER_CERT    = 0xC,
      FEATURE_CERT   = 0xD,
      PKICA_PUBKEY   = 0xE,
      AUTH_CERT_DATA = 0xF
    } SlotCfg;
/*
    const uint32_t sc_sign        = (1 <<  0);
    const uint32_t sc_ecdh        = (1 <<  1);
    const uint32_t sc_ecdh_enc    = (1 <<  2);
    const uint32_t sc_ecdh_pmk    = (1 <<  3);
    const uint32_t sc_priv_write  = (1 <<  4);
    const uint32_t sc_data        = (1 <<  5);
    const uint32_t sc_enc_data    = (1 <<  6);
    const uint32_t sc_pub_key     = (1 <<  7);
    const uint32_t sc_gen_key     = (1 <<  8);

#define AWS_ROOT_CERT_ID    (uint8_t)(0x00)  // Root Cert Identifier
#define AWS_SIGNER_CERT_ID  (uint8_t)(0x01)  // Signer Cert Identifier
#define AWS_VERIF_CERT_ID   (uint8_t)(0x02)  // Verification Cert Identifier
#define AWS_DEVICE_CERT_ID  (uint8_t)(0x03)  // Device Cert Identifier
*/

  public:
    AtCryptoAuthLib();
    ~AtCryptoAuthLib();

    ATCA_STATUS init(const uint8_t* key = NULL);

    ATCA_STATUS set_enc_key(const uint8_t* key = NULL);

    ATCA_STATUS config_locked(bool &lockstate);
    ATCA_STATUS check_config(bool &match);
    ATCA_STATUS config_chip(const uint8_t *access_key = NULL);

    ATCA_STATUS random(uint8_t rand_out[32]);

    ATCA_STATUS get_pub_key(SlotCfg slot, uint8_t pubKey[64]);
    ATCA_STATUS gen_key(SlotCfg slot, uint8_t pubKey[64]);

    ATCA_STATUS priv_key_write(SlotCfg slot, const uint8_t priv_key[32]);

    ATCA_STATUS write_pub_key(SlotCfg slot, const uint8_t pubKey[64]);

    ATCA_STATUS sign(SlotCfg slot, const uint8_t to_sign[32], uint8_t signature[64]);
    ATCA_STATUS sign(const uint8_t to_sign[32], uint8_t signature[64]);

    ATCA_STATUS verify(const uint8_t key[64], const uint8_t to_verify[32],
        const uint8_t signature[64], bool &verify_success);
    ATCA_STATUS verify(SlotCfg slot, const uint8_t to_verify[32],
        const uint8_t signature[64], bool &verify_success);
    ATCA_STATUS verify(const uint8_t to_verify[64],
        const uint8_t signature[64], bool &verify_success);

//    ATCA_STATUS verify_stored(SlotCfg slot, const uint8_t to_verify[32],
//        const uint8_t signature[64], bool &verify_success);

    ATCA_STATUS hash_start();
    ATCA_STATUS hash_update(const uint8_t* data, size_t data_size);
    ATCA_STATUS hash_finish(uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);

    ATCA_STATUS hmac_start(uint8_t *hmac_key, size_t key_size);
    ATCA_STATUS hmac_update(const uint8_t* data, size_t data_size);
    ATCA_STATUS hmac_finish(uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);

    ATCA_STATUS hash(const uint8_t* data, size_t data_size,
        uint8_t digest[ATCA_SHA2_256_DIGEST_SIZE]);

    ATCA_STATUS ecdh_gen_key(uint8_t key[64]);
    ATCA_STATUS ecdh(const uint8_t other_key[64], uint8_t pmk[32], SlotCfg sl = ECDHE_PRIV);

    size_t slot_size(SlotCfg slot);
    bool slot_encrypted(SlotCfg slot);

    ATCA_STATUS read_slot(SlotCfg slot, uint8_t *data, size_t offs, size_t len);
    ATCA_STATUS write_slot(SlotCfg slot, uint8_t *data, size_t offs, size_t len);

    bool verify_cert_chain(uint8_t *caPubKey,
      uint8_t *signerCert, size_t *signerCertSize,
      uint8_t *deviceCert, size_t *deviceCertSize);

// ** Provisioning **
  public:
    int provision_load_signer_cert(
      const char               *pem_cert,
      size_t                    pem_cert_len,
      uint8_t                  *tbs_data, // ATCA_SHA_DIGEST_SIZE
      uint8_t                   signer_id[2],
      const atcacert_tm_utc_t  *issue_date);

  private:
    uint8_t aws_prov_save_cert( uint8_t cert_id, const char *cert_pem,
                                size_t cert_pem_len);

    uint8_t aws_prov_save_signer_public_key(const uint8_t* public_key);

    uint8_t aws_prov_build_device_tbs(
      uint8_t                 *tbs_digest,
      const uint8_t            signer_public_key[64],
      const uint8_t            signer_id[2],
      const atcacert_tm_utc_t* issue_date);

    uint8_t aws_prov_build_tbs_cert_digest(
      const atcacert_def_t*    cert_def,
      uint8_t*                 cert,
      size_t*                  cert_size,
      const uint8_t            ca_public_key[64],
      const uint8_t            public_key[64],
      const uint8_t            signer_id[2],
      const atcacert_tm_utc_t* issue_date,
      const uint8_t            config32[32],
      uint8_t*                 tbs_digest);

  public:
    int provision_save_signature(
      const uint8_t             cert_signature[ATCA_SIG_SIZE],
      const uint8_t             signer_id[2],
      const atcacert_tm_utc_t  *issue_date);

  private:
    uint8_t aws_prov_save_signature(
      uint8_t                   cert_id,
      const uint8_t             cert_signature[ATCA_SIG_SIZE],
      const uint8_t             signer_id[2],
      const atcacert_tm_utc_t  *issue_date);

    uint8_t aws_prov_build_and_save_cert(
      const uint8_t* signature, uint8_t cert_id,
      const uint8_t signer_id[2],
      const atcacert_tm_utc_t *issue_date);

    uint8_t aws_prov_get_signer_public_key(uint8_t* public_key);

  public:
int build_signer_cert(uint8_t *signer_der, size_t *signer_der_size,
      uint8_t *signer_pem, size_t *signer_pem_size);
int build_device_cert(uint8_t *device_der, size_t *device_der_size,
      uint8_t *device_pem, size_t *device_pem_size);


  private:
    // ~100 bytes
//    atcac_sha2_256_ctx sha256_ctx;
    atca_sha256_ctx_t  sha256_ctx;
    bool sha256_init;
    uint8_t m_hmac_key[32];

    uint8_t m_enc_key[ATCA_KEY_SIZE];

    static const uint8_t golden_ecc_configdata[ATCA_CONFIG_SIZE];
    static const uint8_t minimal_ecc_configdata[ATCA_CONFIG_SIZE];

    static const uint8_t ENC_KEY[ATCA_KEY_SIZE];

    ATCA_STATUS atca_tls_init_enc_key();

    static ATCA_STATUS atca_tls_set_enc_key(uint8_t* outKey, int16_t keysize, void *ctx);

//    static const atcacert_def_t my_signer_cert_def;
//    static const atcacert_def_t my_device_cert_def;

/*
Done
 * Sign
 * Verify
 * Hash
 * Get ECDH pub key
 * ECDHE with stored pub key
 * Temp ecc key generation
 * Encrypted set key
 * Encrypted read
 * Encrypted write
 * Clear read
 * Clear write

TODO
 * Cert Chain Verify
 * Read pub keys and certs
 * Verify external cert chain
 * generate challenge
 * Check challenge response
 * Node auth from cert chain and stored pub key
 */


};


#endif // __ATCRYPTOAUTHLIB_H__



