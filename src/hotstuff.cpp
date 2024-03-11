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

#include "hotstuff/hotstuff.h"
#include "hotstuff/client.h"
#include "hotstuff/liveness.h"
#include "secp256k1_frost.h"
using salticidae::static_pointer_cast;

#define LOG_INFO HOTSTUFF_LOG_INFO
#define LOG_DEBUG HOTSTUFF_LOG_DEBUG
#define LOG_WARN HOTSTUFF_LOG_WARN

namespace hotstuff {

const opcode_t MsgPropose::opcode;
MsgPropose::MsgPropose(const Proposal &proposal) {
    std::cout << "---- STO IN MsgPropose riga 31 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    serialized << proposal; }
void MsgPropose::postponed_parse(HotStuffCore *hsc) {
    std::cout << "---- STO IN postponed_parse riga 34 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    proposal.hsc = hsc;
    serialized >> proposal;
}

const opcode_t MsgVote::opcode;
MsgVote::MsgVote(const Vote &vote) {
    std::cout << "---- STO IN MsgVote riga 42 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    serialized << vote; }
void MsgVote::postponed_parse(HotStuffCore *hsc) {
    std::cout << "---- STO IN postponed_parse riga 45 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    vote.hsc = hsc;
    serialized >> vote;
}

const opcode_t MsgReqBlock::opcode;
MsgReqBlock::MsgReqBlock(const std::vector<uint256_t> &blk_hashes) {
    std::cout << "---- STO IN MsgReqBlock riga 53 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    serialized << htole((uint32_t)blk_hashes.size());
    for (const auto &h: blk_hashes)
        serialized << h;
}

MsgReqBlock::MsgReqBlock(DataStream &&s) {
    std::cout << "---- STO IN MsgReqBlock riga 61 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    uint32_t size;
    s >> size;
    size = letoh(size);
    blk_hashes.resize(size);
    for (auto &h: blk_hashes) s >> h;
}

const opcode_t MsgRespBlock::opcode;
MsgRespBlock::MsgRespBlock(const std::vector<block_t> &blks) {
    std::cout << "---- STO IN MsgReqBlock riga 72 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    serialized << htole((uint32_t)blks.size());
    for (auto blk: blks) serialized << *blk;
}

void MsgRespBlock::postponed_parse(HotStuffCore *hsc) {
    std::cout << "---- STO IN postponed_parse riga 78 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    uint32_t size;
    serialized >> size;
    size = letoh(size);
    blks.resize(size);
    for (auto &blk: blks)
    {
        Block _blk;
        _blk.unserialize(serialized, hsc);
        blk = hsc->storage->add_blk(std::move(_blk), hsc->get_config());
    }
}

// TODO: improve this function
void HotStuffBase::exec_command(uint256_t cmd_hash, commit_cb_t callback) {
        std::cout << "---- STO IN exec_command riga 94 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

        cmd_pending.enqueue(std::make_pair(cmd_hash, callback));
}

void HotStuffBase::on_fetch_blk(const block_t &blk) {
    std::cout << "---- STO IN on_fetch_blk riga 100 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

#ifdef HOTSTUFF_BLK_PROFILE
    blk_profiler.get_tx(blk->get_hash());
#endif
    LOG_DEBUG("fetched %.10s", get_hex(blk->get_hash()).c_str());
    part_fetched++;
    fetched++;
    //for (auto cmd: blk->get_cmds()) on_fetch_cmd(cmd);
    const uint256_t &blk_hash = blk->get_hash();
    auto it = blk_fetch_waiting.find(blk_hash);
    if (it != blk_fetch_waiting.end())
    {
        it->second.resolve(blk);
        blk_fetch_waiting.erase(it);
    }
}

bool HotStuffBase::on_deliver_blk(const block_t &blk) {
    std::cout << "---- STO IN on_deliver_blk riga 119 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    
    const uint256_t &blk_hash = blk->get_hash();
    bool valid;
    /* sanity check: all parents must be delivered */
    for (const auto &p: blk->get_parent_hashes())
        assert(storage->is_blk_delivered(p));
    if ((valid = HotStuffCore::on_deliver_blk(blk)))
    {
        LOG_DEBUG("block %.10s delivered",
                get_hex(blk_hash).c_str());
        part_parent_size += blk->get_parent_hashes().size();
        part_delivered++;
        delivered++;
    }
    else
    {
        LOG_WARN("dropping invalid block");
    }

    bool res = true;
    auto it = blk_delivery_waiting.find(blk_hash);
    if (it != blk_delivery_waiting.end())
    {
        auto &pm = it->second;
        if (valid)
        {
            pm.elapsed.stop(false);
            auto sec = pm.elapsed.elapsed_sec;
            part_delivery_time += sec;
            part_delivery_time_min = std::min(part_delivery_time_min, sec);
            part_delivery_time_max = std::max(part_delivery_time_max, sec);

            pm.resolve(blk);
        }
        else
        {
            pm.reject(blk);
            res = false;
            // TODO: do we need to also free it from storage?
        }
        blk_delivery_waiting.erase(it);
    }
    return res;
}

promise_t HotStuffBase::async_fetch_blk(const uint256_t &blk_hash,
                                        const PeerId *replica,
                                        bool fetch_now) {
    std::cout << "---- STO IN async_fetch_blk riga 166 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    if (storage->is_blk_fetched(blk_hash))
        return promise_t([this, &blk_hash](promise_t pm){
            pm.resolve(storage->find_blk(blk_hash));
        });
    auto it = blk_fetch_waiting.find(blk_hash);
    if (it == blk_fetch_waiting.end())
    {
#ifdef HOTSTUFF_BLK_PROFILE
        blk_profiler.rec_tx(blk_hash, false);
#endif
        it = blk_fetch_waiting.insert(
            std::make_pair(
                blk_hash,
                BlockFetchContext(blk_hash, this))).first;
    }
    if (replica != nullptr)
        it->second.add_replica(*replica, fetch_now);
    return static_cast<promise_t &>(it->second);
}

promise_t HotStuffBase::async_deliver_blk(const uint256_t &blk_hash,
                                        const PeerId &replica) {
    std::cout << "---- STO IN async_deliver_blk riga 191 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    if (storage->is_blk_delivered(blk_hash)) {
        std::cout << "BLK IS DELIVERED !!! " << std::endl;
        return promise_t([this, &blk_hash](promise_t pm) {
            pm.resolve(storage->find_blk(blk_hash));
        });
    }
    
    auto it = blk_delivery_waiting.find(blk_hash);
    if (it != blk_delivery_waiting.end())
        return static_cast<promise_t &>(it->second);
    BlockDeliveryContext pm{[](promise_t){}};
    it = blk_delivery_waiting.insert(std::make_pair(blk_hash, pm)).first;
    /* otherwise the on_deliver_batch will resolve */
    async_fetch_blk(blk_hash, &replica).then([this, replica](block_t blk) {
        /* qc_ref should be fetched */
        std::vector<promise_t> pms;
        const auto &qc = blk->get_qc();
        assert(qc);
        if (blk == get_genesis())
            pms.push_back(promise_t([](promise_t &pm){ pm.resolve(true); }));
        else    //verify !!!!!!!!!!!!!!!!!!!!
            pms.push_back(blk->verify(this, vpool));
        pms.push_back(async_fetch_blk(qc->get_obj_hash(), &replica));
        /* the parents should be delivered */
        for (const auto &phash: blk->get_parent_hashes())
            pms.push_back(async_deliver_blk(phash, replica));
        promise::all(pms).then([this, blk](const promise::values_t values) {
            auto ret = promise::any_cast<bool>(values[0]) && this->on_deliver_blk(blk);
            if (!ret)
                HOTSTUFF_LOG_WARN("verification failed during async delivery");
        });
    });
    return static_cast<promise_t &>(pm);
}
/** deliver consensus message:  */
void HotStuffBase::propose_handler(MsgPropose &&msg, const Net::conn_t &conn) {
    std::cout << "---- STO IN propose_handler riga 227 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    const PeerId &peer = conn->get_peer_id();
    if (peer.is_null()) return;
    msg.postponed_parse(this);
    auto &prop = msg.proposal;
    block_t blk = prop.blk;
    if (!blk) return;
    if (peer != get_config().get_peer_id(prop.proposer))
    {
        LOG_WARN("invalid proposal from %d", prop.proposer);
        return;
    }
    promise::all(std::vector<promise_t>{
        async_deliver_blk(blk->get_hash(), peer)
    }).then([this, prop = std::move(prop)]() {
        on_receive_proposal(prop);
    });
}

void HotStuffBase::vote_handler(MsgVote &&msg, const Net::conn_t &conn) {
    std::cout << "---- STO IN vote_handler riga 248 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    const auto &peer = conn->get_peer_id();
    if (peer.is_null()) return;
    msg.postponed_parse(this);
    //auto &vote = msg.vote;
    RcObj<Vote> v(new Vote(std::move(msg.vote)));
    promise::all(std::vector<promise_t>{
        async_deliver_blk(v->blk_hash, peer),
        v->verify(vpool),}).
        then([this, v=std::move(v)](const promise::values_t values) {
        if (!promise::any_cast<bool>(values[1]))
            LOG_WARN("invalid vote from %d", v->voter);
        else
            on_receive_vote(*v);
    });
}

void HotStuffBase::req_blk_handler(MsgReqBlock &&msg, const Net::conn_t &conn) {
    std::cout << "---- STO IN req_blk_handler riga 267 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    const PeerId replica = conn->get_peer_id();
    if (replica.is_null()) return;
    auto &blk_hashes = msg.blk_hashes;
    std::vector<promise_t> pms;
    for (const auto &h: blk_hashes)
        pms.push_back(async_fetch_blk(h, nullptr));
    promise::all(pms).then([replica, this](const promise::values_t values) {
        std::vector<block_t> blks;
        for (auto &v: values)
        {
            auto blk = promise::any_cast<block_t>(v);
            blks.push_back(blk);
        }
        pn.send_msg(MsgRespBlock(blks), replica);
    });
}

void HotStuffBase::resp_blk_handler(MsgRespBlock &&msg, const Net::conn_t &) {
    std::cout << "---- STO IN resp_blk_handler riga 287 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    msg.postponed_parse(this);
    for (const auto &blk: msg.blks)
        if (blk) on_fetch_blk(blk);
}

bool HotStuffBase::conn_handler(const salticidae::ConnPool::conn_t &conn, bool connected) {
    std::cout << "---- STO IN conn_handler riga 295 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    if (connected)
    {
        if (!pn.enable_tls) return true;
        auto cert = conn->get_peer_cert();
        //SALTICIDAE_LOG_INFO("%s", salticidae::get_hash(cert->get_der()).to_hex().c_str());
        return valid_tls_certs.count(salticidae::get_hash(cert->get_der()));
    }
    return true;
}

void HotStuffBase::print_stat() const {
    std::cout << "---- STO IN print_stat riga 308 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    LOG_INFO("===== begin stats =====");
    LOG_INFO("-------- queues -------");
    LOG_INFO("blk_fetch_waiting: %lu", blk_fetch_waiting.size());
    LOG_INFO("blk_delivery_waiting: %lu", blk_delivery_waiting.size());
    LOG_INFO("decision_waiting: %lu", decision_waiting.size());
    LOG_INFO("-------- misc ---------");
    LOG_INFO("fetched: %lu", fetched);
    LOG_INFO("delivered: %lu", delivered);
    LOG_INFO("cmd_cache: %lu", storage->get_cmd_cache_size());
    LOG_INFO("blk_cache: %lu", storage->get_blk_cache_size());
    LOG_INFO("------ misc (10s) -----");
    LOG_INFO("fetched: %lu", part_fetched);
    LOG_INFO("delivered: %lu", part_delivered);
    LOG_INFO("decided: %lu", part_decided);
    LOG_INFO("gened: %lu", part_gened);
    LOG_INFO("avg. parent_size: %.3f",
            part_delivered ? part_parent_size / double(part_delivered) : 0);
    LOG_INFO("delivery time: %.3f avg, %.3f min, %.3f max",
            part_delivered ? part_delivery_time / double(part_delivered) : 0,
            part_delivery_time_min == double_inf ? 0 : part_delivery_time_min,
            part_delivery_time_max);

    part_parent_size = 0;
    part_fetched = 0;
    part_delivered = 0;
    part_decided = 0;
    part_gened = 0;
    part_delivery_time = 0;
    part_delivery_time_min = double_inf;
    part_delivery_time_max = 0;
#ifdef HOTSTUFF_MSG_STAT
    LOG_INFO("--- replica msg. (10s) ---");
    size_t _nsent = 0;
    size_t _nrecv = 0;
    for (const auto &replica: peers)
    {
        auto conn = pn.get_peer_conn(replica);
        if (conn == nullptr) continue;
        size_t ns = conn->get_nsent();
        size_t nr = conn->get_nrecv();
        size_t nsb = conn->get_nsentb();
        size_t nrb = conn->get_nrecvb();
        conn->clear_msgstat();
        LOG_INFO("%s: %u(%u), %u(%u), %u",
            get_hex10(replica).c_str(), ns, nsb, nr, nrb, part_fetched_replica[replica]);
        _nsent += ns;
        _nrecv += nr;
        part_fetched_replica[replica] = 0;
    }
    nsent += _nsent;
    nrecv += _nrecv;
    LOG_INFO("sent: %lu", _nsent);
    LOG_INFO("recv: %lu", _nrecv);
    LOG_INFO("--- replica msg. total ---");
    LOG_INFO("sent: %lu", nsent);
    LOG_INFO("recv: %lu", nrecv);
#endif
    LOG_INFO("====== end stats ======");
}

HotStuffBase::HotStuffBase(uint32_t blk_size,
                    ReplicaID rid,
                    privkey_bt &&priv_key,
                    NetAddr listen_addr,
                    pacemaker_bt pmaker,
                    EventContext ec,
                    size_t nworker,
                    const Net::Config &netconfig):
        HotStuffCore(rid, std::move(priv_key)),
        listen_addr(listen_addr),
        blk_size(blk_size),
        ec(ec),
        tcall(ec),
        vpool(ec, nworker),
        pn(ec, netconfig),
        pmaker(std::move(pmaker)),

        fetched(0), delivered(0),
        nsent(0), nrecv(0),
        part_parent_size(0),
        part_fetched(0),
        part_delivered(0),
        part_decided(0),
        part_gened(0),
        part_delivery_time(0),
        part_delivery_time_min(double_inf),
        part_delivery_time_max(0)
{
    /* register the handlers for msg from replicas */
    pn.reg_handler(salticidae::generic_bind(&HotStuffBase::propose_handler, this, _1, _2));
    pn.reg_handler(salticidae::generic_bind(&HotStuffBase::vote_handler, this, _1, _2));
    pn.reg_handler(salticidae::generic_bind(&HotStuffBase::req_blk_handler, this, _1, _2));
    pn.reg_handler(salticidae::generic_bind(&HotStuffBase::resp_blk_handler, this, _1, _2));
    pn.reg_conn_handler(salticidae::generic_bind(&HotStuffBase::conn_handler, this, _1, _2));
    pn.reg_error_handler([](const std::exception_ptr _err, bool fatal, int32_t async_id) {
        try {
            std::rethrow_exception(_err);
        } catch (const std::exception &err) {
            HOTSTUFF_LOG_WARN("network async error: %s\n", err.what());
        }
    });
    pn.start();
    pn.listen(listen_addr);
}

void HotStuffBase::do_broadcast_proposal(const Proposal &prop) {
    std::cout << "---- STO IN do_broadcast_proposal riga 416 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;


    //MsgPropose prop_msg(prop);
    const std::unordered_map<PeerId, std::vector<uint32_t>> &prova = pn.get_known_peers();
    std::cout << "Map size: " << prova.size() << std::endl;

    for (const auto& pair : prova) {
        const PeerId& peerId = pair.first;
        const std::vector<uint32_t >& integers = pair.second;

        std::cout << "PeerId: " << peerId.to_hex() << ", Integers: ";
        for (int value : integers) {
            std::cout << value << " ";
        }
        std::cout << std::endl;
    }

    pn.multicast_msg(MsgPropose(prop), peers);
    //for (const auto &replica: peers)
    //    pn.send_msg(prop_msg, replica);
}
/**
Called upon sending out a new vote to the next proposer.
 The user should send the vote message to a *good* proposer to have good liveness,
 while safety is always guaranteed by HotStuffCore.
 */
void HotStuffBase::do_vote(ReplicaID last_proposer, const Vote &vote) {
    std::cout << "---- STO IN do_vote riga 425 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    
    pmaker->beat_resp(last_proposer)
            .then([this, vote](ReplicaID proposer) {
        if (proposer == get_id())
        {
            std::cout << "proposer == get_id()" << std::endl;
            
            //throw HotStuffError("unreachable line");
            on_receive_vote(vote);
        }
        else {
            std::cout << "SEND VOTE !!!!" << std::endl;
            
            pn.send_msg(MsgVote(vote), get_config().get_peer_id(proposer));
        }
    });
}

void HotStuffBase::do_consensus(const block_t &blk) {
    std::cout << "---- STO IN do_consensus riga 445 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    
    pmaker->on_consensus(blk);
}

void HotStuffBase::do_decide(Finality &&fin) {
    std::cout << "---- STO IN do_decide riga 451 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;
    
    part_decided++;
    state_machine_execute(fin);
    auto it = decision_waiting.find(fin.cmd_hash);
    if (it != decision_waiting.end())
    {
        it->second(std::move(fin));
        decision_waiting.erase(it);
    }
}

HotStuffBase::~HotStuffBase() {}

void HotStuffBase::start_frost( std::vector<std::tuple<NetAddr, secp256k1_frost_pubkey, uint256_t>> &&replicas,
            bool ec_loop) {
    std::cout << "sto in HotStuffBase::start_frost riga 487 DENTRO hotstuff.cpp package:salticidae->include->src---- \" " << std::endl;
    for (size_t i = 0; i < replicas.size(); i++) {
        auto &addr = std::get<0>(replicas[i]); //<NetAddr 127.0.0.1:10000>
        std::cout << "addr.operator std::string() == " << addr.operator std::string() << std::endl;
        auto cert_hash = std::move(std::get<2>(replicas[i]));   //542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
        std::cout << "cert_hash.to_hex() == " << cert_hash.to_hex() << std::endl;

        valid_tls_certs.insert(cert_hash);
        auto peer = pn.enable_tls ? salticidae::PeerId(cert_hash) : salticidae::PeerId(addr);
        std::cout << " ---  peer.to_hex() = " <<  peer.to_hex() << std::endl;
        //printKeyDER(peer_to_bytes, "peer_to_bytes ");
        auto peer_id = pn.get_peer_id();
        std::cout << "peer_id = " << peer_id.to_hex() << std::endl;
        auto pn_cert = pn.get_cert();
        std::cout << "pn_cert == " <<  get_hex(pn_cert->get_der())<< std::endl;
        //std::cout << "pn_cert.priv == " <<get_hex(pn_cert->get_pubkey().get_privkey_der())<< std::endl;
        std::cout << "pn_cert.pub == " <<get_hex(pn_cert->get_pubkey().get_pubkey_der())<< std::endl;
        HotStuffCore::add_replica_frost(i, peer, std::move(std::get<1>(replicas[i])));
    }

    //todo: continuare
}


void HotStuffBase::start(
        std::vector<std::tuple<NetAddr, pubkey_bt, uint256_t>> &&replicas,
        bool ec_loop) {
    std::cout << "---- STO IN start riga 493 DENTRO hotstuff.cpp package:salticidae->include->src---- " << std::endl;

    for (size_t i = 0; i < replicas.size(); i++)
    {
        auto &addr = std::get<0>(replicas[i]); //<NetAddr 127.0.0.1:10000>
        std::cout << "addr.operator std::string() == " << addr.operator std::string() << std::endl;

        auto cert_hash = std::move(std::get<2>(replicas[i]));   //542865a568784c4e77c172b82e99cb8a1a53b7bee5f86843b04960ea4157f420
        std::cout << "cert_hash.to_hex() == " << cert_hash.to_hex() << std::endl;

        valid_tls_certs.insert(cert_hash);
        /**
         * Il PeerId viene costruito in base al fatto che TLS sia abilitato (pn.enable_tls). Se TLS è abilitato,
         * utilizza l'hash del certificato TLS (cert_hash) per costruire PeerId. Se TLS non è abilitato, utilizza
         * l'hash dell'indirizzo di rete (addr) per costruire il PeerId.

        Quando TLS è abilitato, PeerId viene costruito utilizzando l'hash del certificato
         TLS (cert_hash) e il valore risultante 1218f70519903cbe2fb6bfffcf8583ad81d54bbc4e4d5e3e9392715254f23e92
         è l'ID peer (per replica 0).
         */
        auto peer = pn.enable_tls ? salticidae::PeerId(cert_hash) : salticidae::PeerId(addr);
        std::cout << " ---  peer.to_hex() = " <<  peer.to_hex() << std::endl;
        //printKeyDER(peer_to_bytes, "peer_to_bytes ");
        auto peer_id = pn.get_peer_id();
        std::cout << "peer_id = " << peer_id.to_hex() << std::endl;
        auto pn_cert = pn.get_cert();
        std::cout << "pn_cert == " <<  get_hex(pn_cert->get_der())<< std::endl;
        //std::cout << "pn_cert.priv == " <<get_hex(pn_cert->get_pubkey().get_privkey_der())<< std::endl;
        std::cout << "pn_cert.pub == " <<get_hex(pn_cert->get_pubkey().get_pubkey_der())<< std::endl;


        //auto pubkey = std::move(std::get<1>(replicas[i]));
        //std::cout << "  pubkey->to_hex() = = "<<  pubkey->to_hex() << std::endl;
        //std::cout << "  pubkey.get()->to_hex() = = "<<  pubkey.get()->to_hex() << std::endl;



        /**Add a replica to the current configuration. This should only be called before running
         * HotStuffCore protocol. */
        HotStuffCore::add_replica(i, peer, std::move(std::get<1>(replicas[i])));

        std::cout << "listen_addr.operator std::string() = "<< listen_addr.operator std::string() << std::endl;

        if (addr != listen_addr)
        {
            std::cout << " ---- addr != listen_addr ------" << std::endl;

            // è diverso quando sto nel ciclo relativo a una replica diversa, infatti io
            // sto ciclando per tutte le repliche nel vettore replicas

            //se diversa metto anche gli altri peer nelle strutture che mi servono!
            peers.push_back(peer);

            pn.add_peer(peer);
            pn.set_peer_addr(peer, addr);
            pn.conn_peer(peer);
        }
        std::cout << " #############   " << std::endl;

    } //fine for

    for (const auto& peer : peers) {
        std::cout << "PeerId: " << peer.to_hex() << std::endl;
    }

    // N = 3F+1 --> F = (N-1)/3
    /* ((n - 1) + 1 - 1) / 3 */
    uint32_t nfaulty = peers.size() / 3; //nfaulty = 1
    std::cout << "nfaulty == " << nfaulty << std::endl;
    
    if (nfaulty == 0)
        LOG_WARN("too few replicas in the system to tolerate any failure");
    on_init(nfaulty);//Chiamata per inizializzare il protocollo, dovrebbe essere chiamata una volta prima di tutte le altre funzioni.
    pmaker->init(this);
    std::cout << "FINE PMAKER INIT" << std::endl;
    
    if (ec_loop)
        ec.dispatch();
    std::cout << "-----------------------------  DOPO ec.dispatch() -----------------------------" << std::endl;


    // CI ENTRO SOLO QUANDO RUNNO IL CLIENT !!!!!!!!!!!
    cmd_pending.reg_handler(ec, [this](cmd_queue_t &q) {
        //std::this_thread::sleep_for(std::chrono::seconds(5));

        std::cout << "STO DENTRO cmd_pending.reg_handler(ec, [this](cmd_queue_t &q) " << std::endl;
        
        std::pair<uint256_t, commit_cb_t> e;
        while (q.try_dequeue(e))
        {
            std::cout << "STO NEL WHILE q.try_dequeue(e)" << std::endl;
            
            ReplicaID proposer = pmaker->get_proposer();

            const auto &cmd_hash = e.first;
            auto it = decision_waiting.find(cmd_hash);
            if (it == decision_waiting.end())
                it = decision_waiting.insert(std::make_pair(cmd_hash, e.second)).first;
            else
                e.second(Finality(id, 0, 0, 0, cmd_hash, uint256_t()));
            if (proposer != get_id()) continue;
            cmd_pending_buffer.push(cmd_hash);
            if (cmd_pending_buffer.size() >= blk_size)
            {
                std::vector<uint256_t> cmds;
                for (uint32_t i = 0; i < blk_size; i++)
                {
                    cmds.push_back(cmd_pending_buffer.front());
                    cmd_pending_buffer.pop();
                }
                pmaker->beat().then([this, cmds = std::move(cmds)](ReplicaID proposer) {
                    if (proposer == get_id())
                        on_propose(cmds, pmaker->get_parents());
                });
                return true;
            }
        }
        return false;
    });
}



}
