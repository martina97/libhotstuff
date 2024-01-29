/**
 * Copyright 2018 VMware
 * Copyright 2018 Ted Yin
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <iostream>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <random>
#include <unistd.h>
#include <signal.h>
#include <iostream>
#include <iomanip>

#include "salticidae/stream.h"
#include "salticidae/util.h"
#include "salticidae/network.h"
#include "salticidae/msg.h"

#include "hotstuff/promise.hpp"
#include "hotstuff/type.h"
#include "hotstuff/entity.h"
#include "hotstuff/util.h"
#include "hotstuff/client.h"
#include "hotstuff/hotstuff.h"
#include "hotstuff/liveness.h"

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
        auto cmd = new CommandDummy();
        s >> *cmd;
        return cmd;
    }

    void reset_imp_timer() {
        impeach_timer.del();
        impeach_timer.add(impeach_timeout);
    }

    void state_machine_execute(const Finality &fin) override {
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
};


void printKeyDER(bytearray_t vector1,  const std::string& type_key);

std::pair<std::string, std::string> split_ip_port_cport(const std::string &s) {
    auto ret = trim_all(split(s, ";"));
    if (ret.size() != 2)
        throw std::invalid_argument("invalid cport format");
    return std::make_pair(ret[0], ret[1]);
}

salticidae::BoxObj<HotStuffApp> papp = nullptr;


int main(int argc, char **argv) {
    std::cout << "Hello, world!!!!!!" << std::endl;
    // Print the number of command-line arguments (argc)

    std::cout << "argc: " << argc << std::endl;

    // Print each command-line argument (argv)
    for (int i = 0; i < argc; ++i) {
        std::cout << "argv[" << i << "]: " << argv[i] << std::endl;
    }


    Config config("hotstuff.conf");     // classe che gestisce le opzioni di configurazione per un'applicazione
    std::cout << "---- DOPO CONFIG ---- " << std::endl;
    ElapsedTime elapsed;    //serve a calcolare il tempo trascorso e il tempo della CPU tra due punti nel codice
    elapsed.start();    //tempo di inizio
    std::cout << "---- DOPO elapsed.start() ---- " << std::endl;
    std::cout << "Elapsed time: " << elapsed.elapsed_sec << " seconds\n";
    std::cout << "CPU time: " << elapsed.cpu_elapsed_sec << " seconds\n";

    /*
     * creazione di oggetti OptValInt/OptValDouble/etc
     * ad esempio "opt_blk_size" serve a gestire l'opzione "block-size" di tipo intero:
     Qui viene creato un oggetto di tipo OptValInt chiamato opt_blk_size utilizzando il metodo statico create della classe OptValInt.
     Questo metodo è un modo per creare un'istanza di OptValInt con un valore predefinito (in questo caso 1).

     * L'opzione viene quindi aggiunta all'oggetto Config usando il metodo add_opt.
     * config.add_opt("block-size", opt_blk_size, Config::SET_VAL);
     * Successivamente, l'opzione "block-size" viene aggiunta all'oggetto Config (config) utilizzando
     * il metodo add_opt. Questo metodo richiede il nome dell'opzione, l'oggetto optval_t associato
     * (in questo caso, opt_blk_size), e l'azione associata all'opzione (Config::SET_VAL).
     */
    auto opt_blk_size = Config::OptValInt::create(1);
    auto opt_parent_limit = Config::OptValInt::create(-1);
    auto opt_stat_period = Config::OptValDouble::create(10);
    auto opt_replicas = Config::OptValStrVec::create();
    auto opt_idx = Config::OptValInt::create(0);
    auto opt_client_port = Config::OptValInt::create(-1);
    auto opt_privkey = Config::OptValStr::create();
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
    std::cout << "---- DOPO  config.add_opt ---- " << std::endl;
    std::cout << "opt_privkey->get(): " << opt_privkey->get() << std::endl;
    //opt_blk_size->get()

    EventContext ec;
    config.parse(argc, argv);
    if (opt_help->get())
    {
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


    // Ottieni il vettore di stringhe e stampa i valori
    /*
    const auto& prova = opt_replicas->get();
    for (const auto& s : prova) {
        std::cout << "STO dentro questa cosa : "  << std::endl;

        std::cout << s << std::endl;
    }
    */



    //opt_replicas->get() è un vettore che contiene le righe del file hotstuff.conf, quelle con scritto replicas= ...
    // replicas è un vettore di 4 elementi, ognuno una tupla di 3 elementi, ad esempio:
    //valore1: 127.0.0.1:10000;20000, valore2: 039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23, valore3: 542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
    //valore1: 127.0.0.1:10001;20001, valore2: 0278740a5bec75e333b3c93965b1609163b15d2e3c2fdef141d4859ec70c238e7a, valore3: c261250345ebcd676a0edeea173526608604f626b2e8bc4fd2142d3bde1d44d5
    //valore1: 127.0.0.1:10002;20002, valore2: 0269eb606576a315a630c2483deed35cc4bd845abae1c693f97c440c89503fa92e, valore3: 065b010aed5629edfb5289e8b22fc6cc6b33c4013bfdd128caba80c3c02d6d78
    //valore1: 127.0.0.1:10003;20003, valore2: 03e6911bf17e632eecdfa0dc9fc6efc9ddca60c0e3100db469a3d3d62008044a53, valore3: 6540a0fea67efcb08f53ec3a952df4c3f0e2e07c2778fd92320807717e29a651

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
    //TODO: SCOMMENTARE
    //std::cout << "HotStuffError(\"replica idx out of range\") "  << std::endl;

    // std::get<0>(replicas[idx])  contiene il primo valore della tupla, cioè:
    // replicas[0] = 127.0.0.1:10000;20000 --> replica 0 --> lo scrive in log0
    // replicas[1] = 127.0.0.1:10001;20001 --> replica 1 --> lo scrive in log1
    // replicas[2] = 127.0.0.1:10002;20002 --> replica 2 --> lo scrive in log2
    // replicas[3] = 127.0.0.1:10003;20003 --> replica 3 --> lo scrive in log3

    // Se l'indice è valido, questa riga estrae il primo elemento della tupla corrispondente all'indice idx nel vettore replicas.
    // Presumibilmente, questo primo elemento rappresenta l'indirizzo di binding della replica.
    // Il risultato viene memorizzato nella stringa binding_addr.
    std::string binding_addr = std::get<0>(replicas[idx]);
    std::cout << "binding_addr " << binding_addr << std::endl;

    /*
     * Se `client_port` è -1, viene fatto un tentativo di estrarre la porta dal valore di `binding_addr` usando la
     * funzione `split_ip_port_cport(binding_addr)` e il risultato viene assegnato a `p`.
     * Successivamente, viene tentato di convertire la stringa della porta a un numero intero usando `stoi(p.second, &idx)`.
     * Se la conversione va a buon fine, il valore risultante della porta viene assegnato a `client_port`.
     * Se la conversione fallisce (ad esempio, se la stringa della porta non rappresenta un numero valido),
     * viene generata un'eccezione di tipo `HotStuffError` con il messaggio "client port not specified".
     * */
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
    /*
     * plisten_addr viene creato con l'indirizzo IP ottenuto da binding_addr e con la porta inizializzata a zero (valore predefinito).
     * L'oggetto NetAddr rappresenta quindi un indirizzo IP associato a una determinata porta.
     */
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
    hotstuff::pacemaker_bt pmaker; //pacemaker_bt è BoxObj<PaceMaker>

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

    /** Dichiaro un'istanza della classe "Config" associata alla specializzazione del modello "ClientNetwork" che
     * utilizza il tipo "opcode_t" come parametro del modello "OpcodeType".
     * `ClientNetwork<opcode_t>`: specifica la specializzazione del modello `ClientNetwork` con il tipo `opcode_t`.
     * `::Config`: accede al tipo nidificato `Config` all'interno della classe `ClientNetwork<opcode_t>`.
     * `clinet_config;`: dichiara un'istanza della classe `Config` con il nome `clinet_config`.
     * In sintesi, "clinet_config" è un'istanza della classe di configurazione ("Config") per la specializzazione
     * "ClientNetwork" che utilizza il tipo "opcode_t" per i codici operativi dei messaggi. Questa istanza può essere
     * utilizzata per configurare e inizializzare un oggetto "ClientNetwork".*/
    ClientNetwork<opcode_t>::Config clinet_config;

    /** setto dimensione max dei msgs che possono essere inviati/ricevuti sulle reti corrispondendi */
    repnet_config.max_msg_size(opt_max_rep_msg->get());
    clinet_config.max_msg_size(opt_max_cli_msg->get());
    std::cout << "opt_max_rep_msg->get() " << opt_max_rep_msg->get() <<std::endl;   //ora il proposer è la replica 0, quindi su ogni file di log id_proposer=0
    std::cout << "opt_max_cli_msg->get() " << opt_max_cli_msg->get() <<std::endl;   //ora il proposer è la replica 0, quindi su ogni file di log id_proposer=0

    std::cout << "-----------------------\n" << std::endl;
    std::cout << "opt_tls_privkey == " << opt_tls_privkey->get() << std::endl;
    std::cout << "opt_notls == " << opt_notls->get() << std::endl;  //0

    //std::cout << "hotstuff::from_hex(opt_tls_privkey->get())) == " << hotstuff::from_hex(opt_tls_privkey->get()) << std::endl;
    // opt_tls_privkey è il campo tls-privkey nel file hotstuff-sec{i}.conf, diverso per ogni replica
    if (!opt_tls_privkey->get().empty() && !opt_notls->get())
    {
        /**
         * Creo chiave privata TLS usando il metodo `create_privkey_from_der` della classe `salticidae::PKey`.
         * La chiave privata con codifica DER viene fornita come input a questo metodo, la quale è stata caricata da una stringa con codifica esadecimale (`opt_tls_privkey->get()`).
         * 1. prendo la chiave privata TLS da opt_tls_privkey->get())
         * 2. converto la chiave con codifica esadecimale in un `bytearray_t' (vettore di byte)
         * 3. creo un oggetto `salticidae::PKey` da una chiave privata codificata DER. Accetta "bytearray_t" (chiave codificata DER) come argomento.
         */
        // ###########################      CREAZIONE CHIAVE PRIVATA   ###########################
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

        // opt_tls_cert->get() è il campo tls-cert nel file hotstuff-sec{i}.conf

        // ###########################      CREAZIONE CERTIFICATO   ###########################

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

    std::cout << "Print the hexadecimal representation of the hotstuff::from_hex(opt_privkey->get(): ";
    for (const auto &byte : hotstuff::from_hex(opt_privkey->get())) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    std::cout << std::dec << std::endl;
    std::cout << "plisten_addr --> IP Address: " << std::string(plisten_addr) << std::endl;  //IP Address: <NetAddr 127.0.0.1:10000>
    std::cout << "plisten_addr --> Port: " << ntohs(plisten_addr.port) << std::endl; //Port: 10000

    std::cout << "clisten_addr --> IP Address: " <<  std::string(NetAddr("0.0.0.0", client_port)) << std::endl;
    std::cout << "clisten_addr --> Port: " <<  ntohs(NetAddr("0.0.0.0", client_port).port) << std::endl;
    std::cout << "opt_nworker->get(): " <<   opt_nworker->get() << std::endl;



    // qui chiama pn.start() e cn.start() --> inizio ad ascoltare

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
    //reps contiene tutte le info del file hotstuff.conf:
    //valore1: <NetAddr 127.0.0.1:10000>
    //valore2: 039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23
    //valore3: 542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
    //----
    //valore1: <NetAddr 127.0.0.1:10001>
    //valore2: 0278740a5bec75e333b3c93965b1609163b15d2e3c2fdef141d4859ec70c238e7a
    //valore3: c261250345ebcd676a0edeea173526608604f626b2e8bc4fd2142d3bde1d44d5
    //----
    //valore1: <NetAddr 127.0.0.1:10002>
    //valore2: 0269eb606576a315a630c2483deed35cc4bd845abae1c693f97c440c89503fa92e
    //valore3: 065b010aed5629edfb5289e8b22fc6cc6b33c4013bfdd128caba80c3c02d6d78
    //----
    //valore1: <NetAddr 127.0.0.1:10003>
    //valore2: 03e6911bf17e632eecdfa0dc9fc6efc9ddca60c0e3100db469a3d3d62008044a53
    //valore3: 6540a0fea67efcb08f53ec3a952df4c3f0e2e07c2778fd92320807717e29a651
    //----

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
    auto shutdown = [&](int) { papp->stop(); }; //stopping all threads.
    salticidae::SigEvent ev_sigint(ec, shutdown);
    salticidae::SigEvent ev_sigterm(ec, shutdown);

    ev_sigint.add(SIGINT);
    ev_sigterm.add(SIGTERM);

    papp->start(reps);

    elapsed.stop(true);

    return 0;


}


int main3() {
    std::cout << "Hello, world!!!!!!" << std::endl;
    // Print the number of command-line arguments (argc)

    int argc = 3;

    char *argv[] = {
            "../examples/hotstuff-app",
            "--conf",
            "../hotstuff-sec2.conf" //todo: togliere un . se faccio da terminale
    };

    std::cout << "argc: " << argc << std::endl;

    // Print each command-line argument (argv)

    for (int i = 0; i < argc; ++i) {
        std::cout << "argv[" << i << "]: " << argv[i] << std::endl;
    }
    Config config("../hotstuff.conf");     // classe che gestisce le opzioni di configurazione per un'applicazione
    //todo: scommentare riga dopo se terminale
    //Config config("hotstuff.conf");     // classe che gestisce le opzioni di configurazione per un'applicazione
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
    std::cout << "---- DOPO  config.add_opt ---- " << std::endl;
    std::cout << "opt_privkey->get(): " << opt_privkey->get() << std::endl;

    EventContext ec;
    config.parse(argc, argv);
    if (opt_help->get())
    {
        config.print_help();
        exit(0);
    }
    std::cout << "---- STO QUA ---- " << std::endl;
    auto idx = opt_idx->get();
    std::cout << "idx: " <<idx<< std::endl;

    auto client_port = opt_client_port->get();
    std::cout << "client_port: " <<client_port<< std::endl;

    std::vector<std::tuple<std::string, std::string, std::string>> replicas;
    replicas.push_back(std::make_tuple("127.0.0.1:10000;20000",
                                       "039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23",
                                       "542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420"));

    replicas.push_back(std::make_tuple("127.0.0.1:10001;20001",
                                       "0278740a5bec75e333b3c93965b1609163b15d2e3c2fdef141d4859ec70c238e7a",
                                       "c261250345ebcd676a0edeea173526608604f626b2e8bc4fd2142d3bde1d44d5"));

    replicas.push_back(std::make_tuple("127.0.0.1:10002;20002",
                                       "0269eb606576a315a630c2483deed35cc4bd845abae1c693f97c440c89503fa92e",
                                       "065b010aed5629edfb5289e8b22fc6cc6b33c4013bfdd128caba80c3c02d6d78"));

    replicas.push_back(std::make_tuple("127.0.0.1:10003;20003",
                                       "03e6911bf17e632eecdfa0dc9fc6efc9ddca60c0e3100db469a3d3d62008044a53",
                                       "6540a0fea67efcb08f53ec3a952df4c3f0e2e07c2778fd92320807717e29a651"));

    // Access the elements
    for (const auto& replica : replicas) {
        std::cout << "valore1: " << std::get<0>(replica)
                  << ", valore2: " << std::get<1>(replica)
                  << ", valore3: " << std::get<2>(replica) << std::endl;
    }
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
    hotstuff::pacemaker_bt pmaker; //pacemaker_bt è BoxObj<PaceMaker>

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

    if (!opt_tls_privkey->get().empty() && !opt_notls->get())
    {
        /**
         * Creo chiave privata TLS usando il metodo `create_privkey_from_der` della classe `salticidae::PKey`.
         * La chiave privata con codifica DER viene fornita come input a questo metodo, la quale è stata caricata da una stringa con codifica esadecimale (`opt_tls_privkey->get()`).
         * 1. prendo la chiave privata TLS da opt_tls_privkey->get())
         * 2. converto la chiave con codifica esadecimale in un `bytearray_t' (vettore di byte)
         * 3. creo un oggetto `salticidae::PKey` da una chiave privata codificata DER. Accetta "bytearray_t" (chiave codificata DER) come argomento.
         */
        // ###########################      CREAZIONE CHIAVE PRIVATA   ###########################
        auto tls_priv_key = new salticidae::PKey(
                salticidae::PKey::create_privkey_from_der(
                        hotstuff::from_hex(opt_tls_privkey->get())));

        bytearray_t privkey_der = tls_priv_key->get_privkey_der();
        bytearray_t pubkey_der = tls_priv_key->get_pubkey_der();


        printKeyDER(privkey_der, "priv");
        printKeyDER(pubkey_der, "pub");


        std::cout << "opt_tls_cert->get(): " << opt_tls_cert->get() << std::endl;
        // opt_tls_cert->get() è il campo tls-cert nel file hotstuff-sec{i}.conf

        // ###########################      CREAZIONE CERTIFICATO   ###########################

        auto tls_cert = new salticidae::X509(
                salticidae::X509::create_from_der(
                        hotstuff::from_hex(opt_tls_cert->get())));

        bytearray_t cert_der = tls_cert->get_der();
        // Iterate through the bytes in privkey_der and print them in hexadecimal format
        std::cout << "Print the hexadecimal representation of the certificate: ";
        for (const auto &byte : cert_der) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        // Reset the output stream to decimal mode
        std::cout << std::dec << std::endl;

        bytearray_t pubkey_cert_der = tls_cert->get_pubkey().get_pubkey_der();
        // Iterate through the bytes in privkey_der and print them in hexadecimal format
        std::cout << "Print the hexadecimal representation of the pubkey_cert_der: ";
        for (const auto &byte : pubkey_cert_der) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        // Reset the output stream to decimal mode
        std::cout << std::dec << std::endl;

        // ##############################################

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

    std::cout << "Print the hexadecimal representation of the hotstuff::from_hex(opt_privkey->get(): ";
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
    auto shutdown = [&](int) { papp->stop(); }; //stopping all threads.
    salticidae::SigEvent ev_sigint(ec, shutdown);
    salticidae::SigEvent ev_sigterm(ec, shutdown);
    ev_sigint.add(SIGINT);
    ev_sigterm.add(SIGTERM);
    papp->start(reps);
    return 0;
}



void printKeyDER(bytearray_t privkey_der,  const std::string& type_key) {
    // Stampo DER-encoded private key sottoforma di array: chiave privata con codifica DER in formato esadecimale.
    // output: DER-encoded Private Key: 48 130 4 161 2 1 0 2 130 1 1 0 197 163 88 206 230 28 167 89 45 190 98 205 40 34 84 38 220 63 198 91 51 67 32 67 239 181 232 252 250 243 52 114 11 32 0 209 12 66 33 114 230 249 79 130 116 105 40 166 213 17 147 52 42 21 85 104 78 237 177 65 50 17 112 203 2 204 123 24 159 85 6 204 48 203 92 38 217 184 65 35 50 142 214 223 97 252 26 101 130 176 70 222 247 166 98 187 21 216 78 41 255 162 121 241 216 83 194 92 167 159 190 63 171 2 0 248 200 85 102 165 238 219 152 223 74 149 142 133 18 166 71 37 142 85 167 165 108 28 168 176 86 7 179 139 1 182 162 102 154 249 167 14 250 89 20 31 96 121 52 28 96 68 246 21 104 123 231 86 212 131 14 163 89 19 158 163 94 35 243 76 226 38 33 90 26 47 184 39 28 198 10 3 120 65 228 76 70 14 20 154 113 211 226 250 144 122 72 103 122 209 138 242 231 52 131 67 147 47 95 41 172 82 65 205 32 206 100 230 121 138 218 104 65 100 205 17 9 195 169 105 102 45 154 175 152 151 254 220 90 78 37 110 185 43 247 189 2 1 17 2 130 1 0 81 97 96 205 170 11 204 112 3 198 221 99 136 255 19 151 135 222 6 97 201 208 88 148 113 195 95 239 178 160 96 227 170 58 90 176 110 117 149 77 110 42 108 8 138 73 107 23 132 233 30 126 228 38 230 238 183 22 148 72 5 142 181 249 61 99 65 190 216 50 17 219 155 159 7 211 195 15 162 89 201 134 28 61 221 13 116 71 234 132 209 227 86 234 40 167 99 89 17 32 90 51 215 220 13 200 34 218 219 156 33 41 70 106 60 162 172 215 222 249 8 0 17 197 90 242 73 189 152 227 248 74 84 117 164 60 192 54 156 247 250 94 78 205 209 192 154 192 176 164 27 209 157 138 247 12 173 143 27 106 236 102 162 33 121 229 219 249 196 70 198 69 233 218 169 8 11 69 95 202 100 54 93 142 2 166 134 251 215 7 25 131 2 219 67 205 55 98 144 51 87 69 97 192 37 216 157 41 195 147 116 108 225 47 160 27 190 96 254 179 250 178 146 146 142 173 63 143 109 239 107 154 125 255 205 33 57 246 232 209 247 152 68 210 22 178 141 250 226 157 198 186 140 17 6 49 2 129 129 0 247 112 246 222 161 34 54 221 57 203 70 186 150 193 113 243 207 169 44 150 26 18 191 182 33 8 232 46 11 172 40 5 84 169 173 75 153 196 250 238 146 135 70 117 115 234 246 207 203 163 96 117 54 104 196 10 177 176 21 251 187 149 246 162 211 194 64 41 102 151 31 165 69 64 190 253 195 155 88 150 47 125 12 250 169 111 242 104 223 2 239 171 50 35 133 68 237 117 253 101 134 189 147 227 137 52 201 213 155 3 127 60 215 247 39 179 140 133 78 16 97 222 31 104 191 67 162 109 2 129 129 0 204 121 99 0 32 21 189 89 58 241 82 118 241 133 203 90 52 167 107 179 102 51 200 91 200 108 102 64 65 150 18 165 168 235 44 193 166 173 67 229 28 43 84 95 136 167 232 192 9 106 97 16 184 93 231 209 244 88 236 163 50 103 249 253 230 180 72 158 52 99 4 120 125 51 200 225 3 62 150 181 2 165 62 166 173 44 85 41 156 174 151 55 25 88 125 36 70 143 22 73 48 245 138 86 170 194 199 234 189 104 135 10 16 86 240 107 139 206 197 179 210 21 108 138 19 117 216 145 2 129 128 72 198 223 50 107 160 166 185 137 120 5 190 104 147 63 162 15 230 118 134 128 35 161 204 39 213 113 118 244 95 207 137 24 230 156 97 135 148 73 205 178 160 65 230 79 69 27 106 74 243 209 19 106 91 12 123 157 172 66 179 115 104 87 153 77 87 64 12 45 59 129 199 50 124 116 104 193 15 146 134 134 112 18 224 79 243 191 196 125 211 175 231 14 191 39 50 99 245 134 195 129 251 133 217 130 181 44 77 226 76 82 153 108 178 26 188 86 129 143 110 58 230 250 45 221 230 183 77 2 129 128 24 14 71 225 229 168 52 100 217 194 9 179 163 241 159 116 6 49 208 111 117 111 128 251 189 57 237 233 113 32 182 230 80 27 170 233 155 35 113 102 63 140 160 131 181 185 102 173 46 72 192 32 21 176 177 220 119 25 133 64 96 72 119 195 132 141 174 48 186 222 120 255 29 201 219 101 196 37 123 36 90 170 7 94 231 50 100 95 63 156 17 202 63 55 150 64 128 197 138 38 186 119 61 115 155 158 113 223 97 147 211 166 212 190 239 27 182 24 83 126 145 47 178 106 152 224 176 17 2 129 129 0 149 13 125 94 195 102 248 188 169 24 1 19 89 89 12 110 125 111 228 211 232 146 45 104 70 140 62 36 39 127 39 98 29 177 124 180 29 13 205 223 31 119 226 137 228 157 201 33 1 216 84 78 132 40 30 199 115 47 191 212 233 25 73 36 162 173 172 78 34 239 121 194 173 97 66 143 31 160 62 106 255 163 176 222 7 248 87 222 135 162 231 88 149 49 34 176 214 147 207 73 229 78 222 78 186 68 220 220 44 92 189 103 81 175 81 23 253 16 127 192 228 255 177 143 135 116 215 158
    std::cout << "Print the byte-array representation of " << type_key;

    for (uint8_t value : privkey_der) {
        std::cout << static_cast<int>(value) << " ";
    }
    std::cout << std::endl;


    /* stampo un byte dall'array `privkey_der` come numero esadecimale con larghezza 2 e con riempimento con zero (zero-padding).
     * -`std::hex`: imposta il campo base dello stream su esadecimale, il che significa che i successivi valori interi verranno formattati come numeri esadecimali.
     * -`std::setw(2)`: imposta la larghezza del successivo campo di input o output su 2 caratteri. In questo contesto, garantisce che ogni byte sia rappresentato esattamente da due caratteri nell'output.
     */
    // output: 308204a10201000282010100c5a358cee61ca7592dbe62cd28225426dc3fc65b33432043efb5e8fcfaf334720b2000d10c422172e6f94f82746928a6d51193342a1555684eedb141321170cb02cc7b189f5506cc30cb5c26d9b84123328ed6df61fc1a6582b046def7a662bb15d84e29ffa279f1d853c25ca79fbe3fab0200f8c85566a5eedb98df4a958e8512a647258e55a7a56c1ca8b05607b38b01b6a2669af9a70efa59141f6079341c6044f615687be756d4830ea359139ea35e23f34ce226215a1a2fb8271cc60a037841e44c460e149a71d3e2fa907a48677ad18af2e7348343932f5f29ac5241cd20ce64e6798ada684164cd1109c3a969662d9aaf9897fedc5a4e256eb92bf7bd02011102820100516160cdaa0bcc7003c6dd6388ff139787de0661c9d0589471c35fefb2a060e3aa3a5ab06e75954d6e2a6c088a496b1784e91e7ee426e6eeb7169448058eb5f93d6341bed83211db9b9f07d3c30fa259c9861c3ddd0d7447ea84d1e356ea28a7635911205a33d7dc0dc822dadb9c2129466a3ca2acd7def9080011c55af249bd98e3f84a5475a43cc0369cf7fa5e4ecdd1c09ac0b0a41bd19d8af70cad8f1b6aec66a22179e5dbf9c446c645e9daa9080b455fca64365d8e02a686fbd707198302db43cd37629033574561c025d89d29c393746ce12fa01bbe60feb3fab292928ead3f8f6def6b9a7dffcd2139f6e8d1f79844d216b28dfae29dc6ba8c11063102818100f770f6dea12236dd39cb46ba96c171f3cfa92c961a12bfb62108e82e0bac280554a9ad4b99c4faee9287467573eaf6cfcba360753668c40ab1b015fbbb95f6a2d3c2402966971fa54540befdc39b58962f7d0cfaa96ff268df02efab32238544ed75fd6586bd93e38934c9d59b037f3cd7f727b38c854e1061de1f68bf43a26d02818100cc7963002015bd593af15276f185cb5a34a76bb36633c85bc86c6640419612a5a8eb2cc1a6ad43e51c2b545f88a7e8c0096a6110b85de7d1f458eca33267f9fde6b4489e346304787d33c8e1033e96b502a53ea6ad2c55299cae973719587d24468f164930f58a56aac2c7eabd68870a1056f06b8bcec5b3d2156c8a1375d89102818048c6df326ba0a6b9897805be68933fa20fe676868023a1cc27d57176f45fcf8918e69c61879449cdb2a041e64f451b6a4af3d1136a5b0c7b9dac42b3736857994d57400c2d3b81c7327c7468c10f9286867012e04ff3bfc47dd3afe70ebf273263f586c381fb85d982b52c4de24c52996cb21abc56818f6e3ae6fa2ddde6b74d028180180e47e1e5a83464d9c209b3a3f19f740631d06f756f80fbbd39ede97120b6e6501baae99b2371663f8ca083b5b966ad2e48c02015b0b1dc77198540604877c3848dae30bade78ff1dc9db65c4257b245aaa075ee732645f3f9c11ca3f37964080c58a26ba773d739b9e71df6193d3a6d4beef1bb618537e912fb26a98e0b01102818100950d7d5ec366f8bca918011359590c6e7d6fe4d3e8922d68468c3e24277f27621db17cb41d0dcddf1f77e289e49dc92101d8544e84281ec7732fbfd4e9194924a2adac4e22ef79c2ad61428f1fa03e6affa3b0de07f857de87a2e758953122b0d693cf49e54ede4eba44dcdc2c5cbd6751af5117fd107fc0e4ffb18f8774d79e

    std::cout << "Print the hexadecimal representation of " << type_key;
    // Iterate through the bytes in privkey_der and print them in hexadecimal format
    for (const auto &byte : privkey_der) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }

    // Reset the output stream to decimal mode
    std::cout << std::dec << std::endl;


}


int main2(int argc, char **argv) {
    std::cout << "---- DOPO  config.add_opt ---- " << std::endl;

    Config config("hotstuff.conf");

    ElapsedTime elapsed;
    elapsed.start();

    auto opt_blk_size = Config::OptValInt::create(1);
    auto opt_parent_limit = Config::OptValInt::create(-1);
    auto opt_stat_period = Config::OptValDouble::create(10);
    auto opt_replicas = Config::OptValStrVec::create();
    auto opt_idx = Config::OptValInt::create(0);
    auto opt_client_port = Config::OptValInt::create(-1);
    auto opt_privkey = Config::OptValStr::create();
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

    EventContext ec;
    config.parse(argc, argv);
    if (opt_help->get())
    {
        config.print_help();
        exit(0);
    }
    auto idx = opt_idx->get();
    auto client_port = opt_client_port->get();
    std::vector<std::tuple<std::string, std::string, std::string>> replicas;
    for (const auto &s: opt_replicas->get())
    {
        auto res = trim_all(split(s, ","));
        if (res.size() != 3)
            throw HotStuffError("invalid replica info");
        replicas.push_back(std::make_tuple(res[0], res[1], res[2]));
    }

    //qui
    if (!(0 <= idx && (size_t)idx < replicas.size()))
        throw HotStuffError("replica idx out of range");
    std::string binding_addr = std::get<0>(replicas[idx]);
    //
    if (client_port == -1)
    {
        auto p = split_ip_port_cport(binding_addr);
        size_t idx;
        try {
            client_port = stoi(p.second, &idx);
        } catch (std::invalid_argument &) {
            throw HotStuffError("client port not specified");
        }
    }

    NetAddr plisten_addr{split_ip_port_cport(binding_addr).first};

    //
    auto parent_limit = opt_parent_limit->get();
    hotstuff::pacemaker_bt pmaker;
    if (opt_pace_maker->get() == "dummy")
        pmaker = new hotstuff::PaceMakerDummyFixed(opt_fixed_proposer->get(), parent_limit);
    else
        pmaker = new hotstuff::PaceMakerRR(ec, parent_limit, opt_base_timeout->get(), opt_prop_delay->get());

    //
    HotStuffApp::Net::Config repnet_config;
    //
    ClientNetwork<opcode_t>::Config clinet_config;
    repnet_config.max_msg_size(opt_max_rep_msg->get());
    clinet_config.max_msg_size(opt_max_cli_msg->get());
    //

    if (!opt_tls_privkey->get().empty() && !opt_notls->get())
    {
        auto tls_priv_key = new salticidae::PKey(
                salticidae::PKey::create_privkey_from_der(
                        hotstuff::from_hex(opt_tls_privkey->get())));
        auto tls_cert = new salticidae::X509(
                salticidae::X509::create_from_der(
                        hotstuff::from_hex(opt_tls_cert->get())));
        repnet_config
                .enable_tls(true)
                .tls_key(tls_priv_key)
                .tls_cert(tls_cert);
    }
    repnet_config
            .burst_size(opt_repburst->get())
            .nworker(opt_repnworker->get());
    clinet_config
            .burst_size(opt_cliburst->get())
            .nworker(opt_clinworker->get());
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
        reps.push_back(std::make_tuple(
                NetAddr(p.first),
                hotstuff::from_hex(std::get<1>(r)),
                hotstuff::from_hex(std::get<2>(r))));
    }
    auto shutdown = [&](int) { papp->stop(); };
    salticidae::SigEvent ev_sigint(ec, shutdown);
    salticidae::SigEvent ev_sigterm(ec, shutdown);
    ev_sigint.add(SIGINT);
    ev_sigterm.add(SIGTERM);

    papp->start(reps);
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
    const NetAddr addr = conn->get_addr();
    auto cmd = parse_cmd(msg.serialized);
    const auto &cmd_hash = cmd->get_hash();
    HOTSTUFF_LOG_DEBUG("processing %s", std::string(*cmd).c_str());
    exec_command(cmd_hash, [this, addr](Finality fin) {
        resp_queue.enqueue(std::make_pair(fin, addr));
    });
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



