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

