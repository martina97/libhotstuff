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

#define EXAMPLE_MAX_PARTICIPANTS 4
#define EXAMPLE_MIN_PARTICIPANTS 3


std::pair<std::string, std::string> HotstuffKeyGeneration(const std::string &algo);
std::tuple<std::string, std::string, std::string> HotstuffTLSKeyGeneration();

void writePublicKeyToFile(FILE *pFile, unsigned char key[64], size_t i);

int main() {
    int blocksize = 1;
    const std::string &algo = "secp256k1";
    uint32_t index;
    int return_val;

    if (EXAMPLE_MAX_PARTICIPANTS < 1)
        error(1, 0, "n must be >0");

    /* Open a file in writing mode*/
    FILE *file = fopen("hotstuff_frost.conf", "wb");
    if (file == nullptr) {
        perror("Error opening file");
        return 1;
    }

    // Write block size information to the file
    fprintf(file, "block-size = %d\n", blocksize);
    fprintf(file, "pace-maker = rr\n");

    /** FROST KEY GEN */
    /* secp256k1 context used to sign and verify signatures */
    secp256k1_context *sign_verify_ctx;
    /* This example uses a centralized trusted dealer to generate keys. Alternatively,
     * FROST provides functions to run distributed key generation. See modules/frost/tests_impl.h */
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[4];
    /* keypairs stores private and public keys for each participant */
    secp256k1_frost_keypair keypairs[EXAMPLE_MAX_PARTICIPANTS];
    /* public_keys stores only public keys for each participant (this info can/should be shared among signers) */
    secp256k1_frost_pubkey public_keys[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_signature_share signature_shares[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce *nonces[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce_commitment signing_commitments[EXAMPLE_MAX_PARTICIPANTS];
    /*** Initialization ***/
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    /*** Key Generation ***/
    dealer_commitments = secp256k1_frost_vss_commitments_create(3);
    return_val = secp256k1_frost_keygen_with_dealer(sign_verify_ctx, dealer_commitments,
                                                    shares_by_participant, keypairs,
                                                    EXAMPLE_MAX_PARTICIPANTS, EXAMPLE_MIN_PARTICIPANTS);
    assert(return_val == 1);
    printf("Group Public Key: ");
    print_hex(keypairs[0].public_keys.group_public_key, sizeof(keypairs[0].public_keys.group_public_key));
    printf("\n");
    fprintf(file, "group_public_key = ");
    writePublicKeyToFile(file, keypairs[0].public_keys.group_public_key, sizeof(keypairs[0].public_keys.group_public_key));
    fprintf(file, "\n");

    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) { //per ogni replica
        /*
        //genero pub key e priv key come nel file src/hotstuff_keygen.cpp
        const std::pair<std::string, std::string> &keys = HotstuffKeyGeneration(algo);
        std::string priv_key = keys.first;
        std::string pub_key = keys.second;
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

        secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
        printf("Participant #%d: Secret Key: ", index);
        print_hex(keypairs[index].secret, sizeof(keypairs[index].secret));
        printf("Public Key: ");
        print_hex(keypairs[index].public_keys.public_key, sizeof(keypairs[index].public_keys.public_key));


        /** SCRIVO SUL FILE hotstuff_frost.conf */

        fprintf(file, "replica = 127.0.0.1:%d;%d, ", 10000 + index, 20000 + index);
        //fprintf(file,  "%s, ", pub_key.c_str() );
        writePublicKeyToFile(file, keypairs[index].public_keys.public_key, sizeof(keypairs[index].public_keys.public_key));
        fprintf(file,", ");
        //fprintf(file, "%02x", keypairs[index].public_keys.public_key);
        fprintf(file,  "%s\n", hash_tls_cert.c_str() );


        /** SCRIVO SUL FILE hotstuff_sec{index}.conf */
        std::string file_name = "hotstuff-frost-sec" + std::to_string(index) + ".conf";
        FILE *file2 = fopen(file_name.c_str(), "wb");
        if (file2 == nullptr) {
            perror("Error opening file");
            return 1;
        }
        fprintf(file2, "privkey = ");
        writePublicKeyToFile(file2, keypairs[index].secret, sizeof(keypairs[index].secret));
        fprintf(file2, "\n");
        fprintf(file2, "tls-privkey = %s\n",tls_privkey.c_str());

        //file2 << "privkey = " << priv_key << "\n";
        //file2 << "tls-privkey = " << tls_privkey << "\n";
        fprintf(file2, "tls-cert = %s\n", tls_cert.c_str() );
        //file2 << "tls-cert = " << tls_cert << "\n";
        //file2 << "idx = " << index << "\n";
        fprintf(file2, "idx = %d\n", index);
        fclose(file2);// Chiude il file dopo aver finito di utilizzarlo

    }


    // NEL FILE HOTSTUFF-FROST.CONF ci devo mettere pubkey - cert
    // NEL FILE DELLA SINGOLA REPLICA DEVO METTERE:
    //1 . priv key
    //2.tls-privkey
    //3.tls-cert
    //4. idx

    /* Close the file*/
    // Close the file
    fclose(file);



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

// Write the public_key array to the file
void writePublicKeyToFile(FILE *file, unsigned char public_key[64], size_t size) {
    // Convert the public_key array to its hexadecimal representation
    std::string hexRepresentation;
    char hexBuffer[3];
    for (size_t i = 0; i < size; i++) {
        snprintf(hexBuffer, sizeof(hexBuffer), "%02x", public_key[i]);
        hexRepresentation += hexBuffer;
    }

    // Write the hexadecimal representation to the file
    size_t bytes_written = fwrite(hexRepresentation.c_str(), 1, hexRepresentation.size(), file);

    // Check if the write was successful
    if (bytes_written != hexRepresentation.size()) {
        perror("Error writing to file");
        return;
    }


    printf("Public key written to file successfully.\n");
}