//
// Created by martina on 10/03/24.
//

#include <iostream>
#include <secp256k1_frost.h>
#include <cassert>
#include "salticidae/util.h"
#include "hotstuff/crypto.h"


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
#include "secp256k1.h"

#include "secp256k1_frost.h"
#include "../src/util.h"
#include "../secp256k1-frost/examples/examples_util.h"

#define EXAMPLE_MAX_PARTICIPANTS 4
#define EXAMPLE_MIN_PARTICIPANTS 3

int main(int argc, char* argv[]) {
    std::cout << "Hello, world!!!!!!" << std::endl;

    std::cout << "argc: " << argc << std::endl;

    // Print each command-line argument (argv)
    for (int i = 0; i < argc; ++i) {
        std::cout << "argv[" << i << "]: " << argv[i] << std::endl;
    }
    Config config("hotstuff_frost.conf");
    std::cout << "---- DOPO CONFIG ---- " << std::endl;
    ElapsedTime elapsed;    //serve a calcolare il tempo trascorso e il tempo della CPU tra due punti nel codice
    elapsed.start();    //tempo di inizio
    std::cout << "---- DOPO elapsed.start() ---- " << std::endl;
    std::cout << "Elapsed time: " << elapsed.elapsed_sec << " seconds\n";
    std::cout << "CPU time: " << elapsed.cpu_elapsed_sec << " seconds\n";


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
    if (opt_help->get()) {
        config.print_help();
        exit(0);
    }

    std::cout << "---- STO QUA ---- " << std::endl;
    auto idx = opt_idx->get();
    std::cout << "idx: " <<idx<< std::endl;

    auto client_port = opt_client_port->get();
    std::cout << "client_port: " <<client_port<< std::endl;




}
