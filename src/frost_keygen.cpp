#include <iostream>
#include <string.h>
#include <stdint.h>
#include <fstream>
#include "salticidae/util.h"
#include "hotstuff/crypto.h"


#include <error.h>
#include "secp256k1.h"

#include "secp256k1_frost.h"
#include "../src/util.h"
#include "../secp256k1-frost/examples/examples_util.h"
#include "scalar_4x64.h"
#include "group.h"
#include "int128_native.h"
#include "ecmult_gen.h"


using hotstuff::privkey_bt;
using hotstuff::pubkey_bt;
using hotstuff::tls_pkey_bt;
using hotstuff::tls_x509_bt;

#define EXAMPLE_MAX_PARTICIPANTS 3
#define EXAMPLE_MIN_PARTICIPANTS 2
#define SCALAR_SIZE (32U)
#define SHA256_SIZE (32U)
#define SERIALIZED_PUBKEY_X_ONLY_SIZE (32U)
#define SERIALIZED_PUBKEY_XY_SIZE (64U)
/* Limbs of the secp256k1-hotstuff order. */
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
/* Limbs of 2^256 minus the secp256k1-hotstuff order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)


typedef struct {
    /* Whether the context has been built. */
    int built;

    /* Blinding values used when computing (n-b)G + bG. */
    secp256k1_scalar blind; /* -b */
    secp256k1_gej initial;  /* bG */
} secp256k1_ecmult_gen_context_custom;

struct secp256k1_context_struct {
    secp256k1_ecmult_gen_context_custom ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
    int declassify;
};

static SECP256K1_INLINE void secp256k1_u128_from_u64_custom(secp256k1_uint128 *r, uint64_t a) {
    *r = a;
}
static SECP256K1_INLINE void secp256k1_u128_accum_u64_custom(secp256k1_uint128 *r, uint64_t a) {
    *r += a;
}
static SECP256K1_INLINE uint64_t secp256k1_u128_to_u64_custom(const secp256k1_uint128 *a) {
    return (uint64_t)(*a);
}
static SECP256K1_INLINE void secp256k1_u128_rshift_custom(secp256k1_uint128 *r, unsigned int n) {
    VERIFY_CHECK(n < 128);
    *r >>= n;
}

SECP256K1_INLINE static int secp256k1_scalar_reduce_custom(secp256k1_scalar *r, unsigned int overflow) {
    secp256k1_uint128 t;
    VERIFY_CHECK(overflow <= 1);
    secp256k1_u128_from_u64_custom(&t, r->d[0]);
    secp256k1_u128_accum_u64_custom(&t, overflow * SECP256K1_N_C_0);
    r->d[0] = secp256k1_u128_to_u64_custom(&t); secp256k1_u128_rshift_custom(&t, 64);
    secp256k1_u128_accum_u64_custom(&t, r->d[1]);
    secp256k1_u128_accum_u64_custom(&t, overflow * SECP256K1_N_C_1);
    r->d[1] = secp256k1_u128_to_u64_custom(&t); secp256k1_u128_rshift_custom(&t, 64);
    secp256k1_u128_accum_u64_custom(&t, r->d[2]);
    secp256k1_u128_accum_u64_custom(&t, overflow * SECP256K1_N_C_2);
    r->d[2] = secp256k1_u128_to_u64_custom(&t); secp256k1_u128_rshift_custom(&t, 64);
    secp256k1_u128_accum_u64_custom(&t, r->d[3]);
    r->d[3] = secp256k1_u128_to_u64_custom(&t);
    return overflow;
}

SECP256K1_INLINE static int secp256k1_scalar_check_overflow_custom(const secp256k1_scalar *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a->d[2] < SECP256K1_N_2);
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1);
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

static void secp256k1_scalar_set_b32_custom(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint64_t)b32[31] | (uint64_t)b32[30] << 8 | (uint64_t)b32[29] << 16 | (uint64_t)b32[28] << 24 | (uint64_t)b32[27] << 32 | (uint64_t)b32[26] << 40 | (uint64_t)b32[25] << 48 | (uint64_t)b32[24] << 56;
    r->d[1] = (uint64_t)b32[23] | (uint64_t)b32[22] << 8 | (uint64_t)b32[21] << 16 | (uint64_t)b32[20] << 24 | (uint64_t)b32[19] << 32 | (uint64_t)b32[18] << 40 | (uint64_t)b32[17] << 48 | (uint64_t)b32[16] << 56;
    r->d[2] = (uint64_t)b32[15] | (uint64_t)b32[14] << 8 | (uint64_t)b32[13] << 16 | (uint64_t)b32[12] << 24 | (uint64_t)b32[11] << 32 | (uint64_t)b32[10] << 40 | (uint64_t)b32[9] << 48 | (uint64_t)b32[8] << 56;
    r->d[3] = (uint64_t)b32[7] | (uint64_t)b32[6] << 8 | (uint64_t)b32[5] << 16 | (uint64_t)b32[4] << 24 | (uint64_t)b32[3] << 32 | (uint64_t)b32[2] << 40 | (uint64_t)b32[1] << 48 | (uint64_t)b32[0] << 56;
    over = secp256k1_scalar_reduce_custom(r, secp256k1_scalar_check_overflow_custom(r));
    if (overflow) {
        *overflow = over;
    }
}

static int convert_b32_to_scalar_custom(const unsigned char *hash_value, secp256k1_scalar *output) {
    int overflow = 0;
    secp256k1_scalar_set_b32_custom(output, hash_value, &overflow);
    if (overflow != 0) {
        return 0;
    }
    return 1;
}


static SECP256K1_WARN_UNUSED_RESULT int initialize_random_scalar_custom(secp256k1_scalar *nonce) {
    unsigned char seed[SCALAR_SIZE];
    ssize_t random_bytes;
    random_bytes = getrandom(seed, SCALAR_SIZE, 0);
    if (random_bytes != SCALAR_SIZE) {
        return 0;
    }
    /* Overflow ignored on purpose */
    convert_b32_to_scalar_custom(seed, nonce);
    return 1;
}

SECP256K1_API secp256k1_frost_vss_commitments *secp256k1_frost_vss_commitments_create_custom(uint32_t threshold) {
    uint32_t num_coefficients;
    secp256k1_frost_vss_commitments *vss;
    if (threshold < 1) {
        return NULL;
    }
    num_coefficients = threshold - 1;
    vss = (secp256k1_frost_vss_commitments *) checked_malloc(&default_error_callback,
                                                             sizeof(secp256k1_frost_vss_commitments));
    vss->index = 0;
    memset(vss->zkp_z, 0, SCALAR_SIZE);
    memset(vss->zkp_r, 0, 64);

    vss->num_coefficients = num_coefficients + 1;
    vss->coefficient_commitments = (secp256k1_frost_vss_commitment *)
            checked_malloc(&default_error_callback, (num_coefficients + 1) * sizeof(secp256k1_frost_vss_commitment));
    return vss;
}

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_with_dealer_custom(
        const secp256k1_context_struct *ctx,
        secp256k1_frost_vss_commitments *share_commitment,
        secp256k1_frost_keygen_secret_share *shares,
        secp256k1_frost_keypair *keypairs,
        uint32_t num_participants,
        uint32_t threshold) {
    secp256k1_scalar secret;
    secp256k1_gej group_public_key;
    uint32_t generator_index, index;

    if (ctx == NULL || share_commitment == NULL || shares == NULL || keypairs == NULL) {
        return 0;
    }

    /* We use generator_index=0 as we are generating shares with a dealer */
    generator_index = 0;

    /* Parameter checking */
    if (threshold < 1 || num_participants < 1 || threshold > num_participants) {
        return 0;
    }

    /* Initialization */
    share_commitment->index = generator_index;
    if (initialize_random_scalar_custom(&secret) == 0) {
        return 0;
    }
    //secp256k1_ecmult_gen()

}

std::pair<std::string, std::string> HotstuffKeyGeneration(const std::string &algo);
std::tuple<std::string, std::string, std::string> HotstuffTLSKeyGeneration();

int main() {
    std::cout << "ciao" << std::endl;
    int blocksize = 1;
    int return_val;
    int n = 4;
    const std::string &algo = "secp256k1";
    uint32_t i;

    if (n < 1)
        error(1, 0, "n must be >0");

    /* Open a file in writing mode*/
    std::ofstream file("hotstuff_frost.conf");

    if (file.is_open()) {
        /* Write some text to the file*/
        file << "block-size = " << blocksize << "\n";
        file << "pace-maker = rr\n";

        for (i = 0; i < n; i++) { //per ogni replica
            //genero pub key e priv key come nel file src/hotstuff_keygen.cpp
            const std::pair<std::string, std::string> &keys = HotstuffKeyGeneration(algo);
            std::string priv_key = keys.first;
            std::string pub_key = keys.second;
            /*
            std::cout << priv_key << std::endl;
            std::cout << pub_key << std::endl;
            */

            //genero tls-cert e tls-privkey come nel file src/hotstuff_tls_keygen.cpp
            const std::tuple<std::string, std::string, std::string> &tls_keys = HotstuffTLSKeyGeneration();
            std::string tls_cert = std::get<0>(tls_keys);
            std::string tls_privkey = std::get<1>(tls_keys);
            std::string hash_tls_cert = std::get<2>(tls_keys);
            /*
            std::cout << tls_cert << std::endl;
            std::cout << tls_privkey << std::endl;
            std::cout << hash_tls_cert << std::endl;
            */

            /** SCRIVO SUL FILE hotstuff_frost.conf */
            file << "replica = 127.0.0.1:" << 10000 + i << ";" << 20000 + i << ", ";
            file << pub_key << ", ";
            file << hash_tls_cert << "\n";

            /** SCRIVO SUL FILE hotstuff_sec{i}.conf */
            std::string file_name = "hotstuff-frost-sec" + std::to_string(i) + ".conf";
            std::ofstream file2(file_name);
            file2 << "privkey = " << priv_key << "\n";
            file2 << "tls-privkey = " << tls_privkey << "\n";
            file2 << "tls-cert = " << tls_cert << "\n";
            file2 << "idx = " << i << "\n";

            file2.close(); // Chiude il file dopo aver finito di utilizzarlo
        }
    } else {
        std::cerr << "Impossibile aprire il file." << std::endl;
    }

    // NEL FILE HOTSTUFF-FROST.CONF ci devo mettere pubkey - cert
    // NEL FILE DELLA SINGOLA REPLICA DEVO METTERE:
    //1 . priv key
    //2.tls-privkey
    //3.tls-cert
    //4. idx

    /* Close the file*/
    file.close();


    std::cout << "STO ALLA FINE" << std::endl;
    secp256k1_context_struct *sign_verify_ctx;
    std::cout << "sto qua" << std::endl;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keypair keypairs[EXAMPLE_MAX_PARTICIPANTS];
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);


    dealer_commitments = secp256k1_frost_vss_commitments_create(2);
    /*

    return_val = secp256k1_frost_keygen_with_dealer_custom(sign_verify_ctx, dealer_commitments,
                                                    shares_by_participant, keypairs,
                                                    EXAMPLE_MAX_PARTICIPANTS, EXAMPLE_MIN_PARTICIPANTS);
    assert(return_val == 1);
     */


    return 0;

}


/** Ritorna priv_key e pub_key sottoforma di stringhe */

std::pair<std::string, std::string> HotstuffKeyGeneration(const std::string &algo) {

    privkey_bt priv_key;


    if (algo == "secp256k1")

        priv_key = new hotstuff::PrivKeySecp256k1();

    else

        error(1, 0, "algo not supported");


    priv_key->from_rand();

    pubkey_bt pub_key = priv_key->get_pubkey();

    printf("pub:%s sec:%s\n", get_hex(*pub_key).c_str(), get_hex(*priv_key).c_str());

    std::string priv_key_str = get_hex(*priv_key);

    std::string pub_key_str = get_hex(*pub_key);

    return std::make_pair(priv_key_str, pub_key_str);

}


/** Ritorna tls_cert, tls-privkey e hash(tls_cert) sottoforma di stringhe */

std::tuple<std::string, std::string, std::string> HotstuffTLSKeyGeneration() {

    tls_pkey_bt priv_key;

    tls_x509_bt pub_key;

    priv_key = new salticidae::PKey(salticidae::PKey::create_privkey_rsa());

    pub_key = new salticidae::X509(salticidae::X509::create_self_signed_from_pubkey(*priv_key));

    printf("crt:%s\nsec:%s\ncid:%s\n",

           salticidae::get_hex(pub_key->get_der()).c_str(),

           salticidae::get_hex(priv_key->get_privkey_der()).c_str(),

           salticidae::get_hex(salticidae::get_hash(pub_key->get_der())).c_str());


    std::string tls_cert_str = salticidae::get_hex(pub_key->get_der());

    std::string tls_privkey_str = salticidae::get_hex(priv_key->get_privkey_der());

    std::string hash_tls_cert_str = salticidae::get_hex(salticidae::get_hash(pub_key->get_der()));

    return std::make_tuple(tls_cert_str, tls_privkey_str, hash_tls_cert_str);

}

