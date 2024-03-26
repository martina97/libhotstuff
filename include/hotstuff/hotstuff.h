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

#ifndef _HOTSTUFF_CORE_H
#define _HOTSTUFF_CORE_H

#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <iomanip>
#include <valarray>

#include "salticidae/util.h"
#include "salticidae/network.h"
#include "salticidae/msg.h"
#include "hotstuff/util.h"
#include "hotstuff/consensus.h"
#include "secp256k1_frost.h"
namespace hotstuff {

using salticidae::PeerNetwork;
using salticidae::ElapsedTime;
using salticidae::_1;
using salticidae::_2;

const double ent_waiting_timeout = 10;
const double double_inf = 1e10;

/** Network message format for HotStuff. */
struct MsgPropose {
    static const opcode_t opcode = 0x0;
    DataStream serialized;
    Proposal proposal;
    MsgPropose(const Proposal &);
    /** Only move the data to serialized, do not parse immediately. */
    MsgPropose(DataStream &&s): serialized(std::move(s)) {}
    /** Parse the serialized data to blks now, with `hsc->storage`. */
    void postponed_parse(HotStuffCore *hsc);
};

struct MsgVote {
    static const opcode_t opcode = 0x1;
    DataStream serialized;
    Vote vote;
    MsgVote(const Vote &);
    MsgVote(DataStream &&s): serialized(std::move(s)) {}
    void postponed_parse(HotStuffCore *hsc);
};

struct MsgReqBlock {
    static const opcode_t opcode = 0x2;
    DataStream serialized;
    std::vector<uint256_t> blk_hashes;
    MsgReqBlock() = default;
    MsgReqBlock(const std::vector<uint256_t> &blk_hashes);
    MsgReqBlock(DataStream &&s);
};


struct MsgRespBlock {
    static const opcode_t opcode = 0x3;
    DataStream serialized;
    std::vector<block_t> blks;
    MsgRespBlock(const std::vector<block_t> &blks);
    MsgRespBlock(DataStream &&s): serialized(std::move(s)) {}
    void postponed_parse(HotStuffCore *hsc);
};

using promise::promise_t;

class HotStuffBase;
using pacemaker_bt = BoxObj<class PaceMaker>;

template<EntityType ent_type>
class FetchContext: public promise_t {
    TimerEvent timeout;
    HotStuffBase *hs;
    MsgReqBlock fetch_msg;
    const uint256_t ent_hash;
    std::unordered_set<PeerId> replicas;
    inline void timeout_cb(TimerEvent &);
    public:
    FetchContext(const FetchContext &) = delete;
    FetchContext &operator=(const FetchContext &) = delete;
    FetchContext(FetchContext &&other);

    FetchContext(const uint256_t &ent_hash, HotStuffBase *hs);
    ~FetchContext() {}

    inline void send(const PeerId &replica);
    inline void reset_timeout();
    inline void add_replica(const PeerId &replica, bool fetch_now = true);
};

class BlockDeliveryContext: public promise_t {
    public:
    ElapsedTime elapsed;
    BlockDeliveryContext &operator=(const BlockDeliveryContext &) = delete;
    BlockDeliveryContext(const BlockDeliveryContext &other):
        promise_t(static_cast<const promise_t &>(other)),
        elapsed(other.elapsed) {std::cout << "---- STO IN BlockDeliveryContext riga 112 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
    }
    BlockDeliveryContext(BlockDeliveryContext &&other):
        promise_t(static_cast<const promise_t &>(other)),
        elapsed(std::move(other.elapsed)) {std::cout << "---- STO IN BlockDeliveryContext riga 116 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
    }
    template<typename Func>
    BlockDeliveryContext(Func callback): promise_t(callback) {
        std::cout << "---- STO IN BlockDeliveryContext riga 121 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
        elapsed.start();
    }
};


/** HotStuff protocol (with network implementation). */
class HotStuffBase: public HotStuffCore {
    using BlockFetchContext = FetchContext<ENT_TYPE_BLK>;
    using CmdFetchContext = FetchContext<ENT_TYPE_CMD>;

    friend BlockFetchContext;
    friend CmdFetchContext;

    public:
    using Net = PeerNetwork<opcode_t>;
    using commit_cb_t = std::function<void(const Finality &)>;

    protected:
    /** the binding address in replica network */
    NetAddr listen_addr;
    /** the block size */
    size_t blk_size;
    /** libevent handle */
    EventContext ec;
    salticidae::ThreadCall tcall;
    VeriPool vpool;
    std::vector<PeerId> peers;

    private:
    /** whether libevent handle is owned by itself */
    bool ec_loop;
    /** network stack */
    Net pn;
    std::unordered_set<uint256_t> valid_tls_certs;
#ifdef HOTSTUFF_BLK_PROFILE
    BlockProfiler blk_profiler;
#endif
    pacemaker_bt pmaker;
    /* queues for async tasks */
    std::unordered_map<const uint256_t, BlockFetchContext> blk_fetch_waiting;
    std::unordered_map<const uint256_t, BlockDeliveryContext> blk_delivery_waiting;
    std::unordered_map<const uint256_t, commit_cb_t> decision_waiting;
    using cmd_queue_t = salticidae::MPSCQueueEventDriven<std::pair<uint256_t, commit_cb_t>>;
    cmd_queue_t cmd_pending;
    std::queue<uint256_t> cmd_pending_buffer;

    /* statistics */
    uint64_t fetched;
    uint64_t delivered;
    mutable uint64_t nsent;
    mutable uint64_t nrecv;

    mutable uint32_t part_parent_size;
    mutable uint32_t part_fetched;
    mutable uint32_t part_delivered;
    mutable uint32_t part_decided;
    mutable uint32_t part_gened;
    mutable double part_delivery_time;
    mutable double part_delivery_time_min;
    mutable double part_delivery_time_max;
    mutable std::unordered_map<const PeerId, uint32_t> part_fetched_replica;

    void on_fetch_cmd(const command_t &cmd);
    void on_fetch_blk(const block_t &blk);
    bool on_deliver_blk(const block_t &blk);

    /** deliver consensus message: <propose> */
    inline void propose_handler(MsgPropose &&, const Net::conn_t &);
    /** deliver consensus message: <vote> */
    inline void vote_handler(MsgVote &&, const Net::conn_t &);
    /** fetches full block data */
    inline void req_blk_handler(MsgReqBlock &&, const Net::conn_t &);
    /** receives a block */
    inline void resp_blk_handler(MsgRespBlock &&, const Net::conn_t &);

    inline bool conn_handler(const salticidae::ConnPool::conn_t &, bool);

    void do_broadcast_proposal(const Proposal &) override;
    void do_vote(ReplicaID, const Vote &) override;
    void do_decide(Finality &&) override;
    void do_consensus(const block_t &blk) override;

    protected:

    /** Called to replicate the execution of a command, the application should
     * implement this to make transition for the application state. */
    virtual void state_machine_execute(const Finality &) = 0;

    public:
    HotStuffBase(uint32_t blk_size,
            ReplicaID rid,
            privkey_bt &&priv_key,
            NetAddr listen_addr,
            pacemaker_bt pmaker,
            EventContext ec,
            size_t nworker,
            const Net::Config &netconfig);

    ~HotStuffBase();

    /* the API for HotStuffBase */

    /* Submit the command to be decided. */
    void exec_command(uint256_t cmd_hash, commit_cb_t callback);
    void start(std::vector<std::tuple<NetAddr, pubkey_bt, uint256_t>> &&replicas,
                bool ec_loop = false);
    void start_frost(std::vector<std::tuple<NetAddr, hotstuff::PubKeyFrost, uint256_t>> &&replicas, std::vector<pubkey_bt> &&pubkeyVector, bool ec_loop = false);
   // void start_frost(std::vector<std::tuple<NetAddr, hotstuff::PubKeyFrost, uint256_t>> &&replicas, bool ec_loop = false);

    size_t size() const { return peers.size(); }
    const auto &get_decision_waiting() const { return decision_waiting; }
    ThreadCall &get_tcall() { return tcall; }
    PaceMaker *get_pace_maker() { return pmaker.get(); }
    void print_stat() const;
    virtual void do_elected() {}
//#ifdef HOTSTUFF_AUTOCLI
//    virtual void do_demand_commands(size_t) {}
//#endif

    /* Helper functions */
    /** Returns a promise resolved (with command_t cmd) when Command is fetched. */
    promise_t async_fetch_cmd(const uint256_t &cmd_hash, const PeerId *replica, bool fetch_now = true);
    /** Returns a promise resolved (with block_t blk) when Block is fetched. */
    promise_t async_fetch_blk(const uint256_t &blk_hash, const PeerId *replica, bool fetch_now = true);
    /** Returns a promise resolved (with block_t blk) when Block is delivered (i.e. prefix is fetched). */
    promise_t async_deliver_blk(const uint256_t &blk_hash,  const PeerId &replica);


    };

/** HotStuff protocol (templated by cryptographic implementation). */
template<typename PrivKeyType = PrivKeyDummy,
        typename PubKeyType = PubKeyDummy,
        typename PartCertType = PartCertDummy,
        typename QuorumCertType = QuorumCertDummy>
class HotStuff: public HotStuffBase {
    using HotStuffBase::HotStuffBase;
    protected:

    part_cert_bt create_part_cert(const PrivKey &priv_key, const uint256_t &blk_hash) override {
        std::cout << "---- STO IN create_part_cert riga 258 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
        HOTSTUFF_LOG_DEBUG("create part cert with priv=%s, blk_hash=%s",
                            get_hex10(priv_key).c_str(), get_hex10(blk_hash).c_str());
        std::cout << "PRIMA DI PartCertType" << std::endl;

        auto key = static_cast<const PrivKeyType &>(priv_key);
        /*part_cert_bt certificate = new PartCertType(
                static_cast<const PrivKeyType &>(priv_key),
                blk_hash);*/
        std::cout << "dopo creazione key" << std::endl;
        
        part_cert_bt certificate = new PartCertType(key,blk_hash);
        std::cout << "DOPO PartCertType" << std::endl;
        
        return certificate;
    }

    part_cert_bt parse_part_cert(DataStream &s) override {
        std::cout << "---- STO IN parse_part_cert riga 278 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = "<< s.get_hex()<< std::endl;

        PartCert *pc = new PartCertType();
        s >> *pc;
        return pc;
    }

    quorum_cert_bt create_quorum_cert(const uint256_t &blk_hash, bool frost) override {
        std::cout << "---- STO IN create_quorum_cert riga 286 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

        return new QuorumCertType(get_config(), blk_hash, frost);
    }





    quorum_cert_bt parse_quorum_cert(DataStream &s) override {
        std::cout << "---- STO IN parse_quorum_cert riga 292 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

        QuorumCert *qc = new QuorumCertType();
        s >> *qc;
        return qc;
    }

    public:
    HotStuff(uint32_t blk_size,
            ReplicaID rid,
            const bytearray_t &raw_privkey,
            NetAddr listen_addr,
            pacemaker_bt pmaker,
            EventContext ec = EventContext(),
            size_t nworker = 4,
            const Net::Config &netconfig = Net::Config()):
        HotStuffBase(blk_size,
                    rid,
                    new PrivKeyType(raw_privkey),
                    listen_addr,
                    std::move(pmaker),
                    ec,
                    nworker,
                    netconfig) {}

    void start(const std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> &replicas, bool ec_loop = false) {
        std::cout << "---- STO IN start riga 319 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
        /* VETTORE REPLICAS CONTIENE PER OGNI REPLICA:
         *  valore1: <NetAddr 127.0.0.1:10000>
            valore2: 039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23
            valore3: 542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
         */

        std::vector<std::tuple<NetAddr, pubkey_bt, uint256_t>> reps;
        for (auto &r: replicas)
            reps.push_back(
                std::make_tuple(
                    std::get<0>(r),
                    new PubKeyType(std::get<1>(r)), // 039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23
                    uint256_t(std::get<2>(r))   // 542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
                ));
        HotStuffBase::start(std::move(reps), ec_loop);
    }

    void print_hex2(unsigned char data[64], size_t size) {
        std::cout << "0x";
        for (size_t i = 0; i < size; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        }
        std::cout << std::dec << std::endl; // Reset to decimal format
    }

    void start_frost(const std::vector<std::tuple<NetAddr, bytearray_t, bytearray_t>> &replicas, bytearray_t group_pub_key, bool ec_loop = false) {
        std::cout << "---- STO IN start_frost riga 319 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
        /* VETTORE REPLICAS CONTIENE PER OGNI REPLICA:
         *  valore1: <NetAddr 127.0.0.1:10000>
            valore2: 039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23
            valore3: 542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
         */
        secp256k1_frost_pubkey pubkey;
        bytearray_t bytes_key = std::get<1>(replicas[0]);
        for (const auto &byte : bytes_key) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        std::cout << "\n" << std::endl;
        
        std::memcpy(pubkey.public_key, bytes_key.data(), bytes_key.size());
        print_hex2(pubkey.public_key, sizeof(pubkey.public_key));

        std::memcpy(pubkey.group_public_key, group_pub_key.data(), group_pub_key.size());

        std::vector<std::tuple<NetAddr, hotstuff::PubKeyFrost , uint256_t>> reps;
        std::vector<pubkey_bt> pubkeyVector;

        int index = 0;
        for (auto &r: replicas) {

            const std::vector<uint8_t> &prova = std::move(std::get<1>(r));
            std::vector<uint8_t> concatenated_keys(prova.begin(), prova.end());
            concatenated_keys.insert(concatenated_keys.end(), group_pub_key.begin(), group_pub_key.end());
            std::cout << get_hex(concatenated_keys) << std::endl;

            bytearray_t bytearray_pubkey =  std::move(std::get<1>(r));
            unsigned char* pubkey = new unsigned char[bytearray_pubkey.size()];
            std::copy(bytearray_pubkey.begin(), bytearray_pubkey.end(), pubkey);

            unsigned char* group_pubkey = new unsigned char[group_pub_key.size()];
            std::copy(group_pub_key.begin(), group_pub_key.end(), group_pubkey);

            hotstuff::PubKeyFrost frost_key = hotstuff::PubKeyFrost(pubkey, group_pubkey, index, replicas.size());
            std::cout << frost_key.data->index << std::endl;



            reps.push_back(
                    std::make_tuple(
                            std::get<0>(r),
                            std::move(frost_key), // 039f89215177475ac408d079b45acef4591fc477dd690f2467df052cf0c7baba23
                            uint256_t(std::get<2>(r))   // 542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
                    ));
            index = index +1;
            std::cout << "dentro if index = " << index << std::endl;

            pubkeyVector.push_back(new PubKeyType(std::get<1>(r)));
            
        }
        
        std::cout << "prova stampa puntatori" << std::endl;
        // Access the second element of the tuple, which is hotstuff::PubKeyFrost
        hotstuff::PubKeyFrost &frost_key = std::get<1>(reps[1]);
        // Access the raw pointer to secp256k1_frost_pubkey object
        secp256k1_frost_pubkey* data_ptr = frost_key.data.get();
        print_hex2(data_ptr->group_public_key,33);

        for (std::size_t i = 0; i < 33; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data_ptr->group_public_key[i]);
        }
        std::cout;

        std::cout << "--- STO DOPO START_FROST ------" << std::endl;


        /*
         * unsigned char *pubkey33;
        unsigned char *group_pubkey33;
        secp256k1_frost_pubkey_save(pubkey33, group_pubkey33, frost_key.data.get());
        */
        // Call serializePubKeys with the data_ptr
        auto serializedKeys = frost_key.serializePubKeys();

        // Now you can access the serialized public keys
        unsigned char* pubkey33 = serializedKeys.first.data();
        unsigned char* group_pubkey33 = serializedKeys.second.data();
        print_hex2(pubkey33,33);
        //HotStuffBase::start_frost(std::move(reps), ec_loop);
        HotStuffBase::start_frost(std::move(reps), std::move(pubkeyVector), ec_loop);
    }
};

using HotStuffNoSig = HotStuff<>;
using HotStuffSecp256k1 = HotStuff<PrivKeySecp256k1, PubKeySecp256k1,
                                    PartCertSecp256k1, QuorumCertFrost>;

template<EntityType ent_type>
FetchContext<ent_type>::FetchContext(FetchContext && other):
        promise_t(static_cast<const promise_t &>(other)),
        hs(other.hs),
        fetch_msg(std::move(other.fetch_msg)),
        ent_hash(other.ent_hash),
        replicas(std::move(other.replicas)) {
    std::cout << "---- STO IN FetchContext riga 342 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

    other.timeout.del();
    timeout = TimerEvent(hs->ec,
            std::bind(&FetchContext::timeout_cb, this, _1));
    reset_timeout();
}

template<>
inline void FetchContext<ENT_TYPE_CMD>::timeout_cb(TimerEvent &) {
    std::cout << "---- STO IN timeout_cb riga 357 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

    HOTSTUFF_LOG_WARN("cmd fetching %.10s timeout", get_hex(ent_hash).c_str());
    for (const auto &replica: replicas)
        send(replica);
    reset_timeout();
}

template<>
inline void FetchContext<ENT_TYPE_BLK>::timeout_cb(TimerEvent &) {
    std::cout << "---- STO IN timeout_cb riga 367 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

    HOTSTUFF_LOG_WARN("block fetching %.10s timeout", get_hex(ent_hash).c_str());
    for (const auto &replica: replicas)
        send(replica);
    reset_timeout();
}

template<EntityType ent_type>
FetchContext<ent_type>::FetchContext(
                                const uint256_t &ent_hash, HotStuffBase *hs):
            promise_t([](promise_t){}),
            hs(hs), ent_hash(ent_hash) {
    std::cout << "---- STO IN FetchContext riga 377 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

    fetch_msg = std::vector<uint256_t>{ent_hash};

    timeout = TimerEvent(hs->ec,
            std::bind(&FetchContext::timeout_cb, this, _1));
    reset_timeout();
}

template<EntityType ent_type>
void FetchContext<ent_type>::send(const PeerId &replica) {
    std::cout << "---- STO IN send riga 391 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

    hs->part_fetched_replica[replica]++;
    hs->pn.send_msg(fetch_msg, replica);
}

template<EntityType ent_type>
void FetchContext<ent_type>::reset_timeout() {
    std::cout << "---- STO IN reset_timeout riga 399 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;

    timeout.add(salticidae::gen_rand_timeout(ent_waiting_timeout));
}

template<EntityType ent_type>
void FetchContext<ent_type>::add_replica(const PeerId &replica, bool fetch_now) {
    std::cout << "---- STO IN add_replica riga 406 DENTRO hotstuff.h package:include->hotstuff---- " << std::endl;
    if (replicas.empty() && fetch_now)
        send(replica);
    replicas.insert(replica);
}

}

#endif
