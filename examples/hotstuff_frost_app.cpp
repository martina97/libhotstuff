//
// Created by martina on 10/03/24.
//

#include <iostream>
#include <secp256k1_frost.h>
#include <cassert>
#include "salticidae/util.h"
#include "hotstuff/crypto.h"
#include "secp256k1_frost.h"

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
#include <utility>
#include "secp256k1.h"

#include "secp256k1_frost.h"
#include "../src/util.h"
#include "../secp256k1-frost/examples/examples_util.h"
#define EXAMPLE_MAX_PARTICIPANTS 4
#define EXAMPLE_MIN_PARTICIPANTS 3
using HotStuff = hotstuff::HotStuffSecp256k1;

class HotStuffApp: public HotStuff {
    double stat_period;
    double impeach_timeout;
    EventContext ec;
    EventContext req_ec;
    EventContext resp_ec;
    /** Network messaging between a replica and its client. */
    ClientNetwork<opcode_t> cn;
    /** Timer object to schedule a periodic printing of system statistics */
    TimerEvent ev_stat_timer;
    /** Timer object to monitor the progress for simple impeachment */
    TimerEvent impeach_timer;
    /** The listen address for client RPC */
    NetAddr clisten_addr;

    /** Una mappa non ordinata per tenere traccia degli articoli non confermati. Le chiavi sono di tipo uint256_t e i valori sono promise_t. */
    std::unordered_map<const uint256_t, promise_t> unconfirmed;

    using conn_t = ClientNetwork<opcode_t>::conn_t;
    using resp_queue_t = salticidae::MPSCQueueEventDriven<std::pair<Finality, NetAddr>>;

    /* for the dedicated thread sending responses to the clients */
    std::thread req_thread;
    std::thread resp_thread;
    resp_queue_t resp_queue;
    salticidae::BoxObj<salticidae::ThreadCall> resp_tcall;
    salticidae::BoxObj<salticidae::ThreadCall> req_tcall;

    /** Metodo per gestire i comandi di richiesta del client. Richiede un oggetto MsgReqCmd e un oggetto connessione (conn_t) come parametri.*/
    void client_request_cmd_handler(MsgReqCmd &&, const conn_t &);

    /** Metodo statico per analizzare un comando da un flusso di dati. Crea un oggetto CommandDummy e lo legge dallo stream. */
    static command_t parse_cmd(DataStream &s) {
        std::cout << "---- STO IN parse_cmd DENTRO hotstuff_app.cpp ---- " << std::endl;

        auto cmd = new CommandDummy();
        s >> *cmd;
        return cmd;
    }

    void reset_imp_timer() {
        std::cout << "---- STO IN reset_imp_timer riga 111 DENTRO hotstuff_app.cpp ---- " << std::endl;

        impeach_timer.del();
        impeach_timer.add(impeach_timeout);
    }

    void state_machine_execute(const Finality &fin) override {
        std::cout << "---- STO IN state_machine_execute DENTRO hotstuff_app.cpp ---- " << std::endl;

        reset_imp_timer();
#ifndef HOTSTUFF_ENABLE_BENCHMARK
        HOTSTUFF_LOG_INFO("replicated %s", std::string(fin).c_str());
#endif
    }

#ifdef HOTSTUFF_MSG_STAT
    std::unordered_set<conn_t> client_conns;
    void print_stat() const;
#endif

public:
    HotStuffApp(uint32_t blk_size,
                double stat_period,
                double impeach_timeout,
                ReplicaID idx,
                const bytearray_t &raw_privkey,
                NetAddr plisten_addr,
                NetAddr clisten_addr,
                hotstuff::pacemaker_bt pmaker,
                const EventContext &ec,
                size_t nworker,
                const Net::Config &repnet_config,
                const ClientNetwork<opcode_t>::Config &clinet_config);

    void start(const std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> &reps);
    void stop();

    void start_frost(const std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> &reps, bytearray_t group_pub_key);
};

std::pair<std::string, std::string> split_ip_port_cport(const std::string &s) {
    std::cout << "---- STO IN split_ip_port_cport DENTRO hotstuff_app.cpp ---- " << std::endl;
    auto ret = trim_all(split(s, ";"));
    if (ret.size() != 2)
        throw std::invalid_argument("invalid cport format");
    return std::make_pair(ret[0], ret[1]);
}
salticidae::BoxObj<HotStuffApp> papp = nullptr;

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

    //Dichiaro una variabile replicas che è un vettore di tuple.
    //La tupla ha tre elementi, ognuno di tipo std::string
    //Il vettore replicas può contenere più di queste tuple.
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
    //Verifico se l'indice idx è compreso tra 0 e replicas.size() - 1.
    // Se l'indice non è valido, lancia un'eccezione HotStuffError indicando che l'indice della replica è fuori intervallo.
    if (!(0 <= idx && (size_t)idx < replicas.size()))
        throw HotStuffError("replica idx out of range");

    std::string binding_addr = std::get<0>(replicas[idx]);
    std::cout << "binding_addr " << binding_addr << std::endl;

    if (client_port == -1)
    {
        auto p = split_ip_port_cport(binding_addr);
        std::cout << "p.first: " << p.first << std::endl;
        std::cout << "p.second: " << p.second << std::endl;
        /*
         * ad esempio per la replica 0:
         * p.first: 127.0.0.1:10000 --> indirizzo IP
         * p.second: 20000          --> porta
         */

        size_t idx;
        try {
            client_port = stoi(p.second, &idx);
            std::cout << "client_port: " << client_port << std::endl;
        } catch (std::invalid_argument &) {
            throw HotStuffError("client port not specified");
        }
    }

    NetAddr plisten_addr{split_ip_port_cport(binding_addr).first};
    std::cout << "sto qua dopo plisten_addr " << std::endl;

    std::cout << "IP Address: " << std::string(plisten_addr) << std::endl;  //IP Address: <NetAddr 127.0.0.1:10000>
    std::cout << "Port: " << ntohs(plisten_addr.port) << std::endl; //Port: 10000

    // CONFIGURAZIONE PACEMAKER
    auto parent_limit = opt_parent_limit->get();
    std::cout << "parent_limit: " << parent_limit << std::endl;
    std::cout << "opt_fixed_proposer->get(): " << opt_fixed_proposer->get() << std::endl;
    std::cout << "opt_base_timeout->get(): " << opt_base_timeout->get() << std::endl;
    std::cout << "opt_prop_delay->get(): " << opt_prop_delay->get() << std::endl;
    std::cout << "opt_pace_maker->get(): " << opt_pace_maker->get() << std::endl;
    hotstuff::pacemaker_bt pmaker; //pacemaker_bt è BoxObj<PaceMaker> //todo: FARE IN GO !

    //seleziono un oggetto PaceMaker in base a una condizione specifica.
    if (opt_pace_maker->get() == "dummy") {
        std::cout << "PaceMakerDummyFixed " << std::endl;
        /** creo un oggetto PaceMakerDummyFixed con il proposer fissato e il limite parent specificato */
        pmaker = new hotstuff::PaceMakerDummyFixed(opt_fixed_proposer->get(), parent_limit);
    } else {
        std::cout << "PaceMakerRR " << std::endl;
        /** creo un oggetto PaceMakerRR con l'oggetto EventContext (ec), il limite parent specificato, il timeout di base (opt_base_timeout->get()) e il ritardo del proposer (opt_prop_delay->get())*/
        pmaker = new hotstuff::PaceMakerRR(ec, parent_limit, opt_base_timeout->get(), opt_prop_delay->get());
    }
    std::cout << "sto qua dopo opt_pace_maker " << std::endl;
    std::cout << "pmaker->get_proposer() " << pmaker->get_proposer() <<std::endl;   //ora il proposer è la replica 0, quindi su ogni file di log id_proposer=0

    // -------- FINE PACEMAKER --------

    /*
     * Dichiaro un oggetto della classe Config associata alla classe Net all'interno della classe HotStuffApp.
     * HotStuffApp::Net::Config: fa riferimento alla classe Config definita all'interno della classe Net, che è nidificata all'interno della classe HotStuffApp.
     * Crea un oggetto di configurazione (repnet_config) destinato a configurare le impostazioni relative alla rete associate alla classe HotStuffApp::Net.
     */
    HotStuffApp::Net::Config repnet_config;
    ClientNetwork<opcode_t>::Config clinet_config;

    /** setto dimensione max dei msgs che possono essere inviati/ricevuti sulle reti corrispondendi */
    repnet_config.max_msg_size(opt_max_rep_msg->get());
    clinet_config.max_msg_size(opt_max_cli_msg->get());
    std::cout << "opt_max_rep_msg->get() " << opt_max_rep_msg->get() <<std::endl;   //ora il proposer è la replica 0, quindi su ogni file di log id_proposer=0
    std::cout << "opt_max_cli_msg->get() " << opt_max_cli_msg->get() <<std::endl;   //ora il proposer è la replica 0, quindi su ogni file di log id_proposer=0

    std::cout << "-----------------------\n" << std::endl;
    std::cout << "opt_tls_privkey == " << opt_tls_privkey->get() << std::endl;
    std::cout << "opt_notls == " << opt_notls->get() << std::endl;  //0

    // ORA DEVO CREARE LA CHIAVE TLS --> CODICE UGUALE ALL'ORIGINALE
    if (!opt_tls_privkey->get().empty() && !opt_notls->get())
    {
        auto tls_priv_key = new salticidae::PKey(
                salticidae::PKey::create_privkey_from_der(
                        hotstuff::from_hex(opt_tls_privkey->get())));

        bytearray_t privkey_der = tls_priv_key->get_privkey_der();
        bytearray_t pubkey_der = tls_priv_key->get_pubkey_der();

        std::cout << "priv_key_der = " << hotstuff::get_hex(privkey_der) << std::endl;

        //printKeyDER(privkey_der, "private key");
        //printKeyDER(pubkey_der, "public key");
        std::cout << "get_hex(privkey_der) = " <<hotstuff::get_hex(privkey_der) << std::endl;
        std::cout << "get_hex(pubkey_der) = " <<hotstuff::get_hex(pubkey_der) << std::endl;

        std::cout << "opt_tls_cert = " << opt_tls_cert->get() << std::endl;

        auto tls_cert = new salticidae::X509(
                salticidae::X509::create_from_der(
                        hotstuff::from_hex(opt_tls_cert->get())));

        bytearray_t cert_der = tls_cert->get_der();
        std::cout << "get_hex(cert_der) = "<<hotstuff::get_hex(cert_der) << std::endl;

        bytearray_t pubkey_cert_der = tls_cert->get_pubkey().get_pubkey_der();
        std::cout << "get_hex(pubkey_cert_der) = "<<hotstuff::get_hex(pubkey_cert_der) << std::endl;
        repnet_config
                .enable_tls(true)
                .tls_key(tls_priv_key)
                .tls_cert(tls_cert);
    }
    std::cout << "opt_repburst->get() =" << opt_repburst->get() << std::endl;
    std::cout << "opt_repnworker->get() =" << opt_repnworker->get() << std::endl;
    repnet_config
            .burst_size(opt_repburst->get())    //100
            .nworker(opt_repnworker->get());    //1

    std::cout << "opt_cliburst->get() =" << opt_cliburst->get() << std::endl;
    std::cout << "opt_clinworker->get() =" << opt_clinworker->get() << std::endl;
    clinet_config
            .burst_size(opt_cliburst->get())    //1000
            .nworker(opt_clinworker->get());    //8

    std::cout << "------" << std::endl;
    std::cout << "opt_blk_size->get() =" << opt_blk_size->get() << std::endl;
    std::cout << "opt_stat_period->get() =" << opt_stat_period->get() << std::endl;
    std::cout << "opt_imp_timeout->get() =" << opt_imp_timeout->get() << std::endl;
    std::cout << "idx =" << idx << std::endl;
    std::cout << "Print the hexadecimal representation of the hotstuff::from_hex(opt_privkey->get()): ";
    for (const auto &byte : hotstuff::from_hex(opt_privkey->get())) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << std::endl;
    std::cout << "plisten_addr --> IP Address: " << std::string(plisten_addr) << std::endl;  //IP Address: <NetAddr 127.0.0.1:10000>
    std::cout << "plisten_addr --> Port: " << ntohs(plisten_addr.port) << std::endl; //Port: 10000

    std::cout << "clisten_addr --> IP Address: " <<  std::string(NetAddr("0.0.0.0", client_port)) << std::endl;
    std::cout << "clisten_addr --> Port: " <<  ntohs(NetAddr("0.0.0.0", client_port).port) << std::endl;
    std::cout << "opt_nworker->get(): " <<   opt_nworker->get() << std::endl;

    papp = new HotStuffApp(opt_blk_size->get(),
                           opt_stat_period->get(),
                           opt_imp_timeout->get(),
                           idx,
                           hotstuff::from_hex(opt_privkey->get()),
                           plisten_addr,
                           NetAddr("0.0.0.0", client_port),
                           std::move(pmaker),
                           ec,
                           opt_nworker->get(),
                           repnet_config,
                           clinet_config);

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

    bytearray_t group_pub_key = hotstuff::from_hex(opt_group_pubkey->get());
    std::cout << "STAMPO group_pub_key " << std::endl;

    for (const auto &byte : group_pub_key) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << "\n" << std::endl;
    auto shutdown = [&](int) { papp->stop(); }; //stopping all threads.
    salticidae::SigEvent ev_sigint(ec, shutdown);
    salticidae::SigEvent ev_sigterm(ec, shutdown);

    ev_sigint.add(SIGINT);
    ev_sigterm.add(SIGTERM);

    papp->start_frost(reps, group_pub_key);

    elapsed.stop(true);

    return 0;
}


HotStuffApp::HotStuffApp(uint32_t blk_size,
                         double stat_period,
                         double impeach_timeout,
                         ReplicaID idx,
                         const bytearray_t &raw_privkey,
                         NetAddr plisten_addr,
                         NetAddr clisten_addr,
                         hotstuff::pacemaker_bt pmaker,
                         const EventContext &ec,
                         size_t nworker,
                         const Net::Config &repnet_config,
                         const ClientNetwork<opcode_t>::Config &clinet_config):

        HotStuff(blk_size, idx, raw_privkey,
                 plisten_addr, std::move(pmaker), ec, nworker, repnet_config),
        stat_period(stat_period),
        impeach_timeout(impeach_timeout),
        ec(ec),
        cn(req_ec, clinet_config),
        clisten_addr(clisten_addr) {

    std::cout << "siamo qui2" << std::endl;


    /* prepare the thread used for sending back confirmations */
    resp_tcall = new salticidae::ThreadCall(resp_ec);
    req_tcall = new salticidae::ThreadCall(req_ec);
    resp_queue.reg_handler(resp_ec, [this](resp_queue_t &q) {
        std::pair<Finality, NetAddr> p;
        while (q.try_dequeue(p))
        {
            try {
                cn.send_msg(MsgRespCmd(std::move(p.first)), p.second);
            } catch (std::exception &err) {
                HOTSTUFF_LOG_WARN("unable to send to the client: %s", err.what());
            }
        }
        return false;
    });

    /* register the handlers for msg from clients */
    cn.reg_handler(salticidae::generic_bind(&HotStuffApp::client_request_cmd_handler, this, _1, _2));
    cn.start();
    cn.listen(clisten_addr);
}


void HotStuffApp::client_request_cmd_handler(MsgReqCmd &&msg, const conn_t &conn) {
    std::cout << "---- STO IN client_request_cmd_handler DENTRO hotstuff_app.cpp ---- " << std::endl;

    const NetAddr addr = conn->get_addr();
    auto cmd = parse_cmd(msg.serialized);
    const auto &cmd_hash = cmd->get_hash();
    HOTSTUFF_LOG_DEBUG("processing %s", std::string(*cmd).c_str());
    exec_command(cmd_hash, [this, addr](Finality fin) {
        resp_queue.enqueue(std::make_pair(fin, addr));
    });
}

void HotStuffApp::start_frost(const std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> &reps, bytearray_t group_pub_key) {
    std::cout << "---\n------- Sono in HotStuffApp::start_frost ------ " << std::endl;

    ev_stat_timer = TimerEvent(ec, [this](TimerEvent &) {
        HotStuff::print_stat();
        HotStuffApp::print_stat();
        //HotStuffCore::prune(100);
        ev_stat_timer.add(stat_period);
    });
    ev_stat_timer.add(stat_period);
    impeach_timer = TimerEvent(ec, [this](TimerEvent &) {
        if (get_decision_waiting().size())
            get_pace_maker()->impeach();
        reset_imp_timer();
    });
    impeach_timer.add(impeach_timeout);
    HOTSTUFF_LOG_INFO("** starting the system with parameters **");
    HOTSTUFF_LOG_INFO("blk_size = %lu", blk_size);
    HOTSTUFF_LOG_INFO("conns = %lu", HotStuff::size());
    HOTSTUFF_LOG_INFO("** starting the event loop...");

    HotStuff::start_frost(reps, std::move(group_pub_key));

    cn.reg_conn_handler([this](const salticidae::ConnPool::conn_t &_conn, bool connected) {
        auto conn = salticidae::static_pointer_cast<conn_t::type>(_conn);
        if (connected)
            client_conns.insert(conn);
        else
            client_conns.erase(conn);
        return true;
    });

    req_thread = std::thread([this]() { req_ec.dispatch(); });
    resp_thread = std::thread([this]() { resp_ec.dispatch(); });
    /* enter the event main loop */
    ec.dispatch();
}

void HotStuffApp::start(const std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> &reps) {
    std::cout << "---\n------- Sono in HotStuffApp::start ------ " << std::endl;

    ev_stat_timer = TimerEvent(ec, [this](TimerEvent &) {
        HotStuff::print_stat();
        HotStuffApp::print_stat();
        //HotStuffCore::prune(100);
        ev_stat_timer.add(stat_period);
    });
    ev_stat_timer.add(stat_period);
    impeach_timer = TimerEvent(ec, [this](TimerEvent &) {
        if (get_decision_waiting().size())
            get_pace_maker()->impeach();
        reset_imp_timer();
    });
    impeach_timer.add(impeach_timeout);
    HOTSTUFF_LOG_INFO("** starting the system with parameters **");
    HOTSTUFF_LOG_INFO("blk_size = %lu", blk_size);
    HOTSTUFF_LOG_INFO("conns = %lu", HotStuff::size());
    HOTSTUFF_LOG_INFO("** starting the event loop...");

    HotStuff::start(reps);

    cn.reg_conn_handler([this](const salticidae::ConnPool::conn_t &_conn, bool connected) {
        auto conn = salticidae::static_pointer_cast<conn_t::type>(_conn);
        if (connected)
            client_conns.insert(conn);
        else
            client_conns.erase(conn);
        return true;
    });

    req_thread = std::thread([this]() { req_ec.dispatch(); });
    resp_thread = std::thread([this]() { resp_ec.dispatch(); });
    /* enter the event main loop */
    ec.dispatch();
}

void HotStuffApp::stop() {
    std::cout << "---- STO IN stop DENTRO hotstuff_app.cpp ---- " << std::endl;

    papp->req_tcall->async_call([this](salticidae::ThreadCall::Handle &) {
        req_ec.stop();
    });
    papp->resp_tcall->async_call([this](salticidae::ThreadCall::Handle &) {
        resp_ec.stop();
    });

    req_thread.join();
    resp_thread.join();
    ec.stop();
}

void HotStuffApp::print_stat() const {
    std::cout << "---- STO IN print_stat DENTRO hotstuff_app.cpp ---- " << std::endl;

#ifdef HOTSTUFF_MSG_STAT
    HOTSTUFF_LOG_INFO("--- client msg. (10s) ---");
    size_t _nsent = 0;
    size_t _nrecv = 0;
    for (const auto &conn: client_conns)
    {
        if (conn == nullptr) continue;
        size_t ns = conn->get_nsent();
        size_t nr = conn->get_nrecv();
        size_t nsb = conn->get_nsentb();
        size_t nrb = conn->get_nrecvb();
        conn->clear_msgstat();
        HOTSTUFF_LOG_INFO("%s: %u(%u), %u(%u)",
                          std::string(conn->get_addr()).c_str(), ns, nsb, nr, nrb);
        _nsent += ns;
        _nrecv += nr;
    }
    HOTSTUFF_LOG_INFO("--- end client msg. ---");
#endif
}



