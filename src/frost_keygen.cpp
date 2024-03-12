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
#include "./secp256k1-frost/examples/examples_util.h"
#include "scalar_4x64.h"
#include "group.h"
#include "int128_native.h"
#include "ecmult_gen.h"


#include "../salticidae/include/salticidae/stream.h"
#include "../salticidae/include/salticidae/util.h"
#include "../salticidae/include/salticidae/network.h"
#include "../salticidae/include/salticidae/msg.h"

#include "../include/hotstuff/promise.hpp"
#include "../include/hotstuff/type.h"
#include "../include/hotstuff/entity.h"
#include "../include/hotstuff/util.h"
#include "../include/hotstuff/client.h"
#include "../include/hotstuff/hotstuff.h"
#include "../include/hotstuff/liveness.h"

using salticidae::MsgNetwork;
using salticidae::ClientNetwork;
using salticidae::ElapsedTime;
using salticidae::Config;
using salticidae::_1;
using salticidae::_2;
using salticidae::static_pointer_cast;
using salticidae::trim_all;
using salticidae::split;

using hotstuff::TimerEvent;
using hotstuff::EventContext;
using hotstuff::NetAddr;
using hotstuff::HotStuffError;
using hotstuff::CommandDummy;
using hotstuff::Finality;
using hotstuff::command_t;
using hotstuff::uint256_t;
using hotstuff::opcode_t;
using hotstuff::bytearray_t;
using hotstuff::DataStream;
using hotstuff::ReplicaID;
using hotstuff::MsgReqCmd;
using hotstuff::MsgRespCmd;
using hotstuff::get_hash;
using hotstuff::promise_t;
#include <error.h>
#include <iomanip>
#include "secp256k1.h"
using hotstuff::privkey_bt;
using hotstuff::pubkey_bt;
using hotstuff::tls_pkey_bt;
using hotstuff::tls_x509_bt;

#define EXAMPLE_MAX_PARTICIPANTS 4
#define EXAMPLE_MIN_PARTICIPANTS 3


std::pair<std::string, std::string> HotstuffKeyGeneration(const std::string &algo);
std::tuple<std::string, std::string, std::string> HotstuffTLSKeyGeneration();
std::pair<std::string, std::string> split_ip_port_cport(const std::string &s);
void writePublicKeyToFile(FILE *pFile, unsigned char key[64], size_t i);

int main2() {


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
    writePublicKeyToFile(file, keypairs[0].public_keys.group_public_key,
                         sizeof(keypairs[0].public_keys.group_public_key));
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
        writePublicKeyToFile(file, keypairs[index].public_keys.public_key,
                             sizeof(keypairs[index].public_keys.public_key));
        fprintf(file, ", ");
        //fprintf(file, "%02x", keypairs[index].public_keys.public_key);
        fprintf(file, "%s\n", hash_tls_cert.c_str());


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
        fprintf(file2, "tls-privkey = %s\n", tls_privkey.c_str());

        //file2 << "privkey = " << priv_key << "\n";
        //file2 << "tls-privkey = " << tls_privkey << "\n";
        fprintf(file2, "tls-cert = %s\n", tls_cert.c_str());
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

    // Close the file
    fclose(file);
    return 0;
}

int main(int argc, char* argv[]) {

    std::cout << "\n\n\nPROVO A FARE PROCESSO INVERSO DAL FILE DI CONFIGURAZIONE" << std::endl;
    Config config("hotstuff_frost.conf");
    std::cout << "---- DOPO CONFIG ---- " << std::endl;

    auto opt_blk_size = Config::OptValInt::create(1);
    auto opt_parent_limit = Config::OptValInt::create(-1);
    auto opt_stat_period = Config::OptValDouble::create(10);
    auto opt_replicas = Config::OptValStrVec::create();
    auto opt_idx = Config::OptValInt::create(0);
    auto opt_client_port = Config::OptValInt::create(-1);
    auto opt_privkey = Config::OptValStr::create();
    auto opt_group_pubkey = Config::OptValStr::create();
    auto opt_tls_privkey = Config::OptValStr::create();
    auto opt_tls_cert = Config::OptValStr::create();
    auto opt_help = Config::OptValFlag::create(false);
    auto opt_pace_maker = Config::OptValStr::create("dummy");
    auto opt_fixed_proposer = Config::OptValInt::create(1);
    auto opt_base_timeout = Config::OptValDouble::create(1);
    auto opt_prop_delay = Config::OptValDouble::create(1);
    auto opt_imp_timeout = Config::OptValDouble::create(11);
    auto opt_nworker = Config::OptValInt::create(1);
    auto opt_repnworker = Config::OptValInt::create(1);
    auto opt_repburst = Config::OptValInt::create(100);
    auto opt_clinworker = Config::OptValInt::create(8);
    auto opt_cliburst = Config::OptValInt::create(1000);
    auto opt_notls = Config::OptValFlag::create(false);
    auto opt_max_rep_msg = Config::OptValInt::create(4 << 20); // 4M by default
    auto opt_max_cli_msg = Config::OptValInt::create(65536); // 64K by default

    config.add_opt("block-size", opt_blk_size, Config::SET_VAL);
    config.add_opt("parent-limit", opt_parent_limit, Config::SET_VAL);
    config.add_opt("stat-period", opt_stat_period, Config::SET_VAL);
    config.add_opt("replica", opt_replicas, Config::APPEND, 'a', "add an replica to the list");
    config.add_opt("idx", opt_idx, Config::SET_VAL, 'i', "specify the index in the replica list");
    config.add_opt("cport", opt_client_port, Config::SET_VAL, 'c', "specify the port listening for clients");
    config.add_opt("privkey", opt_privkey, Config::SET_VAL);
    config.add_opt("group_public_key", opt_group_pubkey, Config::SET_VAL);
    config.add_opt("tls-privkey", opt_tls_privkey, Config::SET_VAL);
    config.add_opt("tls-cert", opt_tls_cert, Config::SET_VAL);
    config.add_opt("pace-maker", opt_pace_maker, Config::SET_VAL, 'p', "specify pace maker (dummy, rr)");
    config.add_opt("proposer", opt_fixed_proposer, Config::SET_VAL, 'l', "set the fixed proposer (for dummy)");
    config.add_opt("base-timeout", opt_base_timeout, Config::SET_VAL, 't', "set the initial timeout for the Round-Robin Pacemaker");
    config.add_opt("prop-delay", opt_prop_delay, Config::SET_VAL, 't', "set the delay that follows the timeout for the Round-Robin Pacemaker");
    config.add_opt("imp-timeout", opt_imp_timeout, Config::SET_VAL, 'u', "set impeachment timeout (for sticky)");
    config.add_opt("nworker", opt_nworker, Config::SET_VAL, 'n', "the number of threads for verification");
    config.add_opt("repnworker", opt_repnworker, Config::SET_VAL, 'm', "the number of threads for replica network");
    config.add_opt("repburst", opt_repburst, Config::SET_VAL, 'b', "");
    config.add_opt("clinworker", opt_clinworker, Config::SET_VAL, 'M', "the number of threads for client network");
    config.add_opt("cliburst", opt_cliburst, Config::SET_VAL, 'B', "");
    config.add_opt("notls", opt_notls, Config::SWITCH_ON, 's', "disable TLS");
    config.add_opt("max-rep-msg", opt_max_rep_msg, Config::SET_VAL, 'S', "the maximum replica message size");
    config.add_opt("max-cli-msg", opt_max_cli_msg, Config::SET_VAL, 'S', "the maximum client message size");
    config.add_opt("help", opt_help, Config::SWITCH_ON, 'h', "show this help info");

    //STAMPO I VALORI DI CONFIG !!!!
    std::cout << "---- DOPO  config.add_opt ---- " << std::endl;
    std::cout << "opt_privkey->get(): " << opt_privkey->get() << std::endl;


    EventContext ec;
    config.parse(argc, argv);
    std::vector<std::tuple<std::string, std::string, std::string>> replicas;




    for (const auto &s: opt_replicas->get())
    {
        //std::cout << "STO dentro if : "  << std::endl;
        auto res = trim_all(split(s, ","));
        if (res.size() != 3)
            throw HotStuffError("invalid replica info");
        replicas.push_back(std::make_tuple(res[0], res[1], res[2]));
    }
    // Stampa il contenuto del vettore
    for (const auto& replica : replicas) {
        std::cout << "valore1: " << std::get<0>(replica) << ", "
                  << "valore2: " << std::get<1>(replica) << ", "
                  << "valore3: " << std::get<2>(replica) << std::endl;
    }

    std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> reps;
    for (auto &r: replicas)
    {
        auto p = split_ip_port_cport(std::get<0>(r));
        std::cout << " p.first == " << p.first << std::endl;
        std::cout << " p.second == " << p.second << std::endl;

        reps.push_back(std::make_tuple(
                NetAddr(p.first),
                hotstuff::from_hex(std::get<1>(r)),
                hotstuff::from_hex(std::get<2>(r))));
    }
    // Stampa il contenuto del vettore reps
    std::cout << "\n--------\nCONTENUTO VETTORE reps:" << std::endl;

    for (const auto& rep : reps) {

        auto ip_addr = std::string(std::get<0>(rep));
        bytearray_t arr1 = std::get<1>(rep);
        bytearray_t arr2 = std::get<2>(rep);


        std::cout << "valore1: " << ip_addr << std::endl;
        std::cout << "valore2: ";
        for (const auto &byte : arr1) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << std::dec << std::endl;
        std::cout << "valore3: ";
        for (const auto &byte : arr2) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << std::dec << std::endl;
        std::cout << "----" << std::endl;

    }

    std::cout << "\nPROVO CONVERSIONE" << std::endl;

    std::vector<std::tuple<NetAddr, pubkey_bt, uint256_t>> reps2;
    /*
    for (auto &r: reps) {
        secp256k1_frost_pubkey pubkey;
        bytearray_t bytes_key = std::get<1>(r);
        for (const auto &byte : bytes_key) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::memcpy(pubkey.public_key, bytes_key.data(), bytes_key.size());
        std::cout << "\n" << std::endl;

    }
     */
    salticidae::RcObj<Config::OptValStr> &pubkey_string = opt_group_pubkey;
    std::cout << "pubkey_string->get() = " << pubkey_string->get() << std::endl;
    std::cout << "STAMPO PROVA" << std::endl;

    bytearray_t prova = hotstuff::from_hex(pubkey_string->get());
    for (const auto &byte : prova) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << "\n" << std::endl;


    secp256k1_frost_pubkey pubkey;
    bytearray_t bytes_key = std::get<1>(reps[0]);
    for (const auto &byte : bytes_key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << "\n" << std::endl;
    std::memcpy(pubkey.public_key, bytes_key.data(), bytes_key.size());
    std::memcpy(pubkey.group_public_key, prova.data(), prova.size());

    print_hex(pubkey.public_key, sizeof(pubkey.public_key));
    print_hex(pubkey.group_public_key, sizeof(pubkey.group_public_key));


    return 0;

}


std::pair<std::string, std::string> split_ip_port_cport(const std::string &s) {
    std::cout << "---- STO IN split_ip_port_cport DENTRO hotstuff_app.cpp ---- " << std::endl;
    auto ret = trim_all(split(s, ";"));
    if (ret.size() != 2)
        throw std::invalid_argument("invalid cport format");
    return std::make_pair(ret[0], ret[1]);
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