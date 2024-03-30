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

int EXAMPLE_MAX_PARTICIPANTS2;
int EXAMPLE_MIN_PARTICIPANTS2;



std::pair<std::string, std::string> HotstuffKeyGeneration(const std::string &algo);
std::tuple<std::string, std::string, std::string> HotstuffTLSKeyGeneration();
std::pair<std::string, std::string> split_ip_port_cport(const std::string &s);
void writePublicKeyToFile(FILE *pFile, unsigned char key[64], size_t i);

int main(int argc, char* argv[]) {
    // Print each command-line argument (argv)
    if (argc >= 2) {
        for (int i = 0; i < argc; ++i) {
            std::cout << "argv[" << i << "]: " << argv[i] << std::endl;

        }
        EXAMPLE_MAX_PARTICIPANTS2 = std::stoi(argv[1]);
        EXAMPLE_MIN_PARTICIPANTS2 = std::stoi(argv[2]);
    } else {
        std::cerr << "Errore: Passare almeno un argomento\n";
        return 1; // Uscita con errore
    }



    unsigned char msg[] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[] = "frost_protocol";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;
    int blocksize = 1;
    const std::string &algo = "secp256k1";
    uint32_t index;
    int return_val;

    if (EXAMPLE_MAX_PARTICIPANTS2 < 1)
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
    secp256k1_frost_keygen_secret_share shares_by_participant[EXAMPLE_MAX_PARTICIPANTS2];
    /* keypairs stores private and public keys for each participant */
    secp256k1_frost_keypair keypairs[EXAMPLE_MAX_PARTICIPANTS2];
    /* public_keys stores only public keys for each participant (this info can/should be shared among signers) */
    secp256k1_frost_pubkey public_keys[EXAMPLE_MAX_PARTICIPANTS2];
    secp256k1_frost_signature_share signature_shares[EXAMPLE_MAX_PARTICIPANTS2];
    secp256k1_frost_nonce *nonces[EXAMPLE_MAX_PARTICIPANTS2];
    secp256k1_frost_nonce_commitment signing_commitments[EXAMPLE_MAX_PARTICIPANTS2];
    /*** Initialization ***/
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    /*** Key Generation ***/
    dealer_commitments = secp256k1_frost_vss_commitments_create(EXAMPLE_MIN_PARTICIPANTS2);
    return_val = secp256k1_frost_keygen_with_dealer(sign_verify_ctx, dealer_commitments,
                                                    shares_by_participant, keypairs,
                                                    EXAMPLE_MAX_PARTICIPANTS2, EXAMPLE_MIN_PARTICIPANTS2);
    assert(return_val == 1);
    printf("Group Public Key: ");
    print_hex(keypairs[0].public_keys.group_public_key, sizeof(keypairs[0].public_keys.group_public_key));
    printf("\n");
    fprintf(file, "group_public_key = ");
    unsigned char pubkey[33];
    unsigned char group_pubkey[33];
    secp256k1_frost_pubkey_save(pubkey, group_pubkey, &keypairs[0].public_keys);
    writePublicKeyToFile(file, group_pubkey,sizeof(group_pubkey));
    fprintf(file, "\n");

    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS2; index++) { //per ogni replica
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
        /*
        printf("Participant #%d: Secret Key: ", index);
        print_hex(keypairs[index].secret, sizeof(keypairs[index].secret));
        printf("Public Key: ");
        print_hex(keypairs[index].public_keys.public_key, sizeof(keypairs[index].public_keys.public_key));
         */

        unsigned char pubkey[33];
        unsigned char group_pubkey[33];
        secp256k1_frost_pubkey_save(pubkey, group_pubkey, &keypairs[index].public_keys);
        printf("Participant #%d: Secret Key: ", index);
        print_hex(keypairs[index].secret, sizeof(keypairs[index].secret));
        printf("Public Key: ");
        print_hex(pubkey, sizeof(pubkey));
        printf("Group public Key: ");
        print_hex(group_pubkey, sizeof(group_pubkey));
        /** SCRIVO SUL FILE hotstuff_frost.conf */

        fprintf(file, "replica = 127.0.0.1:%d;%d, ", 10000 + index, 20000 + index);
        //fprintf(file,  "%s, ", pub_key.c_str() );
        writePublicKeyToFile(file, pubkey, sizeof(pubkey));
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
    fclose(file);
    return 0;
}

int main3(int argc, char* argv[]) {

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
    salticidae::RcObj<Config::OptValStr> &group_pubkey_string = opt_group_pubkey;
    std::cout << "group_pubkey = " << group_pubkey_string->get() << std::endl;
    std::cout << "STAMPO PROVA" << std::endl;

    bytearray_t prova = hotstuff::from_hex(group_pubkey_string->get());
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


    // FINORA HO CREATO LA CHIAVE PUBBLICA, ORA PROVO A PRENDERE LA PRIVATA
    salticidae::RcObj<Config::OptValStr> &priv_key_string = opt_privkey;
    std::cout << "priv_key_string = " << priv_key_string->get() << std::endl;

    std::vector<std::array<unsigned char, 32>> cVector(4);
    const char* hexString1 = "a116fda7a0c50a75a03d6059409537127ca4d4b61fd81d5be4b0c6e8d86748e6";
    const char* hexString2 = "46bc5debf2347d760acbe0ddfb461f58929f4498c41a2578350c5011fe515efe";
    const char* hexString3= "83bc0427f1f20b164e6130b84d36efbd05db212c243e12a8ce884074a0c56e5d";
    const char* hexString4 = "5815f05b9ffdb3566afd4fe83667a8411ba98d8990fb44b1f1523983ef8d35c2";
// Convert hex string to unsigned char array
    unsigned char secret[32];
    for (std::size_t i = 0, j = 0; i < 32 * 2; i += 2, ++j) {
        std::string byteString = {hexString1[i], hexString1[i + 1]};
        secret[j] = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
    }

    std::cout << "\nPRINT SECRET" << std::endl;
    
    // Print the array
    for (std::size_t i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(secret[i]);
    }
    std::cout << std::endl;
    // Assign each element of secret to cVector[0]
    for (std::size_t i = 0; i < 64; ++i) {
        cVector[0][i] = secret[i];
    }

    for (std::size_t i = 0, j = 0; i < 32 * 2; i += 2, ++j) {
        std::string byteString = {hexString2[i], hexString2[i + 1]};
        secret[j] = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
    }

    std::cout << "\nPRINT SECRET" << std::endl;
    for (std::size_t i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(secret[i]);
    }
    for (std::size_t i = 0; i < 32; ++i) {
        cVector[1][i] = secret[i];
    }

    for (std::size_t i = 0, j = 0; i < 32 * 2; i += 2, ++j) {
        std::string byteString = {hexString3[i], hexString3[i + 1]};
        secret[j] = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
    }

    std::cout << "\nPRINT SECRET" << std::endl;
    for (std::size_t i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(secret[i]);
    }
    for (std::size_t i = 0; i < 32; ++i) {
        cVector[2][i] = secret[i];
    }
    for (std::size_t i = 0, j = 0; i < 32 * 2; i += 2, ++j) {
        std::string byteString = {hexString4[i], hexString4[i + 1]};
        secret[j] = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
    }

    std::cout << "\nPRINT SECRET" << std::endl;
    for (std::size_t i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(secret[i]);
    }
    for (std::size_t i = 0; i < 32; ++i) {
        cVector[2][i] = secret[i];
    }
    std::cout << "\n" << std::endl;
    
    int i = 0;
    for (const auto& rep : reps) {
        secp256k1_frost_pubkey pubkey;
        bytearray_t bytes_key = std::get<1>(rep);
        std::memcpy(pubkey.public_key, bytes_key.data(), bytes_key.size());
        std::memcpy(pubkey.group_public_key, prova.data(), prova.size());
        print_hex(pubkey.public_key, sizeof(pubkey.public_key));
        secp256k1_frost_keypair key_pair;
        std::memcpy(key_pair.public_keys.public_key, bytes_key.data(), bytes_key.size());
        std::memcpy(key_pair.public_keys.group_public_key, prova.data(), prova.size());
        auto ok = cVector[0].data();
        print_hex(ok,sizeof(ok));
        

    }

    std::cout << cVector[0].size() << std::endl;
    
    std::cout << "DA QUI INIZIA PROVA" << std::endl;


    unsigned char msg[13] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[15] = "frost_protocol";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;

    return 0;

}

std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
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

int main2() {
    unsigned char msg[13] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[15] = "frost_protocol";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;
    uint32_t index;
    int return_val;

    if (EXAMPLE_MAX_PARTICIPANTS2 < 1)
        error(1, 0, "n must be >0");


    /** FROST KEY GEN */
    /* secp256k1 context used to sign and verify signatures */
    secp256k1_context *sign_verify_ctx;
    /* This example uses a centralized trusted dealer to generate keys. Alternatively,
     * FROST provides functions to run distributed key generation. See modules/frost/tests_impl.h */
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[4];
    /* keypairs stores private and public keys for each participant */
    secp256k1_frost_keypair keypairs[EXAMPLE_MAX_PARTICIPANTS2];
    /* public_keys stores only public keys for each participant (this info can/should be shared among signers) */
    secp256k1_frost_pubkey public_keys[EXAMPLE_MAX_PARTICIPANTS2];
    secp256k1_frost_signature_share signature_shares[EXAMPLE_MAX_PARTICIPANTS2];
    secp256k1_frost_nonce *nonces[EXAMPLE_MAX_PARTICIPANTS2];
    secp256k1_frost_nonce_commitment signing_commitments[EXAMPLE_MAX_PARTICIPANTS2];
    /*** Initialization ***/
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    /*** Key Generation ***/
    dealer_commitments = secp256k1_frost_vss_commitments_create(3);
    return_val = secp256k1_frost_keygen_with_dealer(sign_verify_ctx, dealer_commitments,
                                                    shares_by_participant, keypairs,
                                                    EXAMPLE_MAX_PARTICIPANTS2, EXAMPLE_MIN_PARTICIPANTS2);
    assert(return_val == 1);
    printf("Group Public Key: ");
    print_hex(keypairs[0].public_keys.group_public_key, sizeof(keypairs[0].public_keys.group_public_key));
    printf("\n");


    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS2; index++) { //per ogni replica

        secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
        printf("Participant #%d: Secret Key: ", index);
        print_hex(keypairs[index].secret, sizeof(keypairs[index].secret));
        printf("Public Key: ");
        print_hex(keypairs[index].public_keys.public_key, sizeof(keypairs[index].public_keys.public_key));

    }
    /*** Signing ***/
    /* In FROST, each signer needs to generate a nonce for each signature to compute. A nonce commitment is
     * exchanged among signers to prevent forgery of signature aggregations. */

    /* Nonce:
     * Participants to the signing process generate a new nonce and share the related commitment */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS2; index++) {

        /* Generate 32 bytes of randomness to use for computing the nonce. */
        if (!fill_random(binding_seed, sizeof(binding_seed))) {
            printf("Failed to generate binding_seed\n");
            return 1;
        }
        if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
            printf("Failed to generate hiding_seed\n");
            return 1;
        }

        /* Create the nonce (the function already computes its commitment) */
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx, &keypairs[index],
                                                     binding_seed, hiding_seed);
        /* Copying secp256k1_frost_nonce_commitment to a shared array across participants */
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }
    std::cout << "sto quaaa" << std::endl;
    /* Instead of signing (possibly very long) messages directly, we sign a 32-byte hash of the message.
    * We use secp256k1_tagged_sha256 to create this hash.  */
    return_val = secp256k1_tagged_sha256(sign_verify_ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
    assert(return_val == 1);


    /* Signature Share:
    * At least EXAMPLE_MIN_PARTICIPANTS participants compute a signature share. These
    * signature shares will be then aggregated to compute a single FROST signature. */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS2; index++) {
        /* The secp256k1_frost_sign function provides a simple interface for signing 32-byte messages
         * (which in our case is a hash of the actual message).
         * Besides the message (msg_hash in this case), the function requires the number of other signers,
         * the private signer keypair and nonce, and the public signing commitments of other participants.
         */
        return_val = secp256k1_frost_sign(&(signature_shares[index]), msg_hash, EXAMPLE_MIN_PARTICIPANTS2,
                                          &keypairs[index], nonces[index], signing_commitments);
        assert(return_val == 1);
    }
    return_val = secp256k1_frost_aggregate(sign_verify_ctx, signature, msg_hash,
                                           &keypairs[0], public_keys, signing_commitments,
                                           signature_shares, EXAMPLE_MIN_PARTICIPANTS2);
    assert(return_val == 1);

    /*** Verification ***/
    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
    is_signature_valid = secp256k1_frost_verify(sign_verify_ctx, signature, msg_hash, &keypairs[0].public_keys);


/* Print signature and participant keys */
    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    /* This will clear everything from the context and free the memory */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS2; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
    // NEL FILE HOTSTUFF-FROST.CONF ci devo mettere pubkey - cert
    // NEL FILE DELLA SINGOLA REPLICA DEVO METTERE:
    //1 . priv key
    //2.tls-privkey
    //3.tls-cert
    //4. idx

    // Close the file

    return 0;
}
