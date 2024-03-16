/**
 * Copyright 2018 VMware
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

#ifndef _HOTSTUFF_ENT_H
#define _HOTSTUFF_ENT_H

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <cstddef>
#include <ios>

#include "salticidae/netaddr.h"
#include "salticidae/ref.h"
#include "hotstuff/type.h"
#include "hotstuff/util.h"
#include "hotstuff/crypto.h"
#include "secp256k1_frost.h"
namespace hotstuff {

enum EntityType {
    ENT_TYPE_CMD = 0x0,
    ENT_TYPE_BLK = 0x1
};

struct ReplicaInfo {
    ReplicaID id;
    salticidae::PeerId peer_id;
    pubkey_bt pubkey;

    ReplicaInfo(ReplicaID id,
                const salticidae::PeerId &peer_id,
                pubkey_bt &&pubkey):
        id(id), peer_id(peer_id), pubkey(std::move(pubkey)) {std::cout << "---- STO IN ReplicaInfo riga 45 DENTRO entity.h package:include->hotstuff---- " << std::endl;
    }

    ReplicaInfo(const ReplicaInfo &other):
        id(other.id), peer_id(other.peer_id),
        pubkey(other.pubkey->clone()) {std::cout << "---- STO IN ReplicaInfo riga 51 DENTRO entity.h package:include->hotstuff---- " << std::endl;
    }

    ReplicaInfo(ReplicaInfo &&other):
        id(other.id), peer_id(other.peer_id),
        pubkey(std::move(other.pubkey)) {std::cout << "---- STO IN ReplicaInfo riga 56 DENTRO entity.h package:include->hotstuff---- " << std::endl;
    }
};

struct ReplicaInfoFrost {
    ReplicaID id;
    salticidae::PeerId peer_id;
    pubkey_bt pubkey;

    ReplicaInfoFrost(ReplicaID id,
                const salticidae::PeerId &peer_id,
                     pubkey_bt &&pubkey):
            id(id), peer_id(peer_id), pubkey(std::move(pubkey)) {std::cout << "---- STO IN ReplicaInfo riga 45 DENTRO entity.h package:include->hotstuff---- " << std::endl;
    }

    ReplicaInfoFrost(const ReplicaInfoFrost &other):
            id(other.id), peer_id(other.peer_id),
            pubkey(other.pubkey->clone()) {std::cout << "---- STO IN ReplicaInfo riga 51 DENTRO entity.h package:include->hotstuff---- " << std::endl;
    }

    ReplicaInfoFrost(ReplicaInfoFrost &&other):
            id(other.id), peer_id(other.peer_id),
            pubkey(std::move(other.pubkey)) {std::cout << "---- STO IN ReplicaInfo riga 56 DENTRO entity.h package:include->hotstuff---- " << std::endl;
    }
};

class ReplicaConfig {
    std::unordered_map<ReplicaID, ReplicaInfo> replica_map;
    std::unordered_map<ReplicaID, ReplicaInfoFrost> replica_map_frost;

    public:
    size_t nreplicas;
    size_t nmajority;

    ReplicaConfig(): nreplicas(0), nmajority(0) {}

    void add_replica(ReplicaID rid, const ReplicaInfo &info) {
        std::cout << "---- STO IN add_replica riga 71 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        replica_map.insert(std::make_pair(rid, info));
        nreplicas++;
    }
    /*
    void add_replica(ReplicaID rid, const ReplicaInfoFrost &info) {
        std::cout << "---- STO IN add_replica riga 71 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        replica_map_frost.insert(std::make_pair(rid, info));
        nreplicas++;
        secp256k1_frost_pubkey key = info.pubkey;
        size_t i;
        printf("0x");
        for (i = 0; i < sizeof(key.public_key); i++) {
            printf("%02x", key.public_key[i]);
        }
        printf("\n");
        printf("0x");
        for (i = 0; i < sizeof(key.group_public_key); i++) {
            printf("%02x", key.group_public_key[i]);
        }
        printf("\n");
        std::cout << "dopo add_replica" << std::endl;

    }
     */

    const ReplicaInfo &get_info(ReplicaID rid) const {
        std::cout << "---- STO IN get_info riga 78 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        auto it = replica_map.find(rid);
        if (it == replica_map.end())
            throw HotStuffError("rid %s not found",
                    get_hex(rid).c_str());
        return it->second;
    }

    const PubKey &get_pubkey(ReplicaID rid) const {
        std::cout << "---- STO IN get_pubkey riga 88 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return *(get_info(rid).pubkey);
    }

    const salticidae::PeerId &get_peer_id(ReplicaID rid) const {
        std::cout << "---- STO IN get_peer_id riga 94 DENTRO entity.h package:include->hotstuff---- " << std::endl;
        return get_info(rid).peer_id;
    }
};

class Block;
class HotStuffCore;

using block_t = salticidae::ArcObj<Block>;

class Command: public Serializable {
    friend HotStuffCore;
    public:
    virtual ~Command() = default;
    virtual const uint256_t &get_hash() const = 0;
    virtual bool verify() const = 0;
    virtual operator std::string () const {
        DataStream s;
        s << "<cmd id=" << get_hex10(get_hash()) << ">";
        return s;
    }
};

using command_t = ArcObj<Command>;

template<typename Hashable>
inline static std::vector<uint256_t>
get_hashes(const std::vector<Hashable> &plist) {
    std::cout << "---- STO IN get_hashes riga 122 DENTRO entity.h package:include->hotstuff---- " << std::endl;

    std::vector<uint256_t> hashes;
    for (const auto &p: plist)
        hashes.push_back(p->get_hash());
    return hashes;
}

class Block {
    friend HotStuffCore;
    std::vector<uint256_t> parent_hashes;
    std::vector<uint256_t> cmds;
    quorum_cert_bt qc_old;
    quorum_cert_bt qc;
    bytearray_t extra;

    /* the following fields can be derived from above */
    uint256_t hash;
    std::vector<block_t> parents;
    block_t qc_ref;
    quorum_cert_bt self_qc;
    uint32_t height;
    bool delivered;
    int8_t decision;

    std::unordered_set<ReplicaID> voted;

    public:
    Block():
        qc(nullptr),
        qc_ref(nullptr),
        self_qc(nullptr), height(0),
        delivered(false), decision(0) {}

    Block(bool delivered, int8_t decision):
        qc(new QuorumCertDummy()),
        hash(salticidae::get_hash(*this)),
        qc_ref(nullptr),
        self_qc(nullptr), height(0),
        delivered(delivered), decision(decision) {}

    Block(const std::vector<block_t> &parents,
        const std::vector<uint256_t> &cmds,
        quorum_cert_bt &&qc,
        bytearray_t &&extra,
        uint32_t height,
        const block_t &qc_ref,
        quorum_cert_bt &&self_qc,
        int8_t decision = 0):
            parent_hashes(get_hashes(parents)),
            cmds(cmds),
            qc(std::move(qc)),
            extra(std::move(extra)),
            hash(salticidae::get_hash(*this)),
            parents(parents),
            qc_ref(qc_ref),
            self_qc(std::move(self_qc)),
            height(height),
            delivered(0),
            decision(decision) {}

    void serialize(DataStream &s) const;

    void unserialize(DataStream &s, HotStuffCore *hsc);

    const std::vector<uint256_t> &get_cmds() const {
        std::cout << "---- STO IN get_cmds riga 187 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return cmds;
    }

    const std::vector<block_t> &get_parents() const {
        std::cout << "---- STO IN get_parents riga 193 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return parents;
    }

    const std::vector<uint256_t> &get_parent_hashes() const {
        std::cout << "---- STO IN get_parent_hashes riga 199 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return parent_hashes;
    }

    const uint256_t &get_hash() const { return hash; }

    bool verify(const HotStuffCore *hsc) const;

    promise_t verify(const HotStuffCore *hsc, VeriPool &vpool) const;

    int8_t get_decision() const {
        std::cout << "---- STO IN get_decision riga 211 DENTRO entity.h package:include->hotstuff---- " << std::endl;
        return decision; }

    bool is_delivered() const {
        std::cout << "---- STO IN is_delivered riga 215 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return delivered; }

    uint32_t get_height() const {        std::cout << "---- STO IN get_height riga 220 DENTRO entity.h package:include->hotstuff---- " << std::endl;
        return height; }

    const quorum_cert_bt &get_qc() const { return qc; }

    const block_t &get_qc_ref() const { return qc_ref; }

    const bytearray_t &get_extra() const { return extra; }

    operator std::string () const {
        std::cout << "---- STO IN std::string riga 229 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        DataStream s;
        s << "<block "
          << "id="  << get_hex10(hash) << " "
          << "height=" << std::to_string(height) << " "
          << "parent=" << get_hex10(parent_hashes[0]) << " "
          << "qc_ref=" << (qc_ref ? get_hex10(qc_ref->get_hash()) : "null") << ">";
        return s;
    }
};

struct BlockHeightCmp {
    bool operator()(const block_t &a, const block_t &b) const {
        return a->get_height() < b->get_height();
    }
};

class EntityStorage {
    std::unordered_map<const uint256_t, block_t> blk_cache;
    std::unordered_map<const uint256_t, command_t> cmd_cache;
    public:
    bool is_blk_delivered(const uint256_t &blk_hash) {
        std::cout << "---- STO IN is_blk_delivered riga 252 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        auto it = blk_cache.find(blk_hash);
        if (it == blk_cache.end()) return false;
        return it->second->is_delivered();
    }

    bool is_blk_fetched(const uint256_t &blk_hash) {
        std::cout << "---- STO IN is_blk_fetched riga 260 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return blk_cache.count(blk_hash);
    }

    block_t add_blk(Block &&_blk, const ReplicaConfig &/*config*/) {
        std::cout << "---- STO IN add_blk riga 266 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        //if (!_blk.verify(config))
        //{
        //    HOTSTUFF_LOG_WARN("invalid %s", std::string(_blk).c_str());
        //    return nullptr;
        //}
        block_t blk = new Block(std::move(_blk));
        return blk_cache.insert(std::make_pair(blk->get_hash(), blk)).first->second;
    }

    const block_t &add_blk(const block_t &blk) {
        std::cout << "---- STO IN add_blk riga 278 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return blk_cache.insert(std::make_pair(blk->get_hash(), blk)).first->second;
    }

    block_t find_blk(const uint256_t &blk_hash) {
        std::cout << "---- STO IN find_blk riga 285 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        auto it = blk_cache.find(blk_hash);
        return it == blk_cache.end() ? nullptr : it->second;
    }

    bool is_cmd_fetched(const uint256_t &cmd_hash) {
        std::cout << "---- STO IN is_cmd_fetched riga 291 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return cmd_cache.count(cmd_hash);
    }

    const command_t &add_cmd(const command_t &cmd) {
        std::cout << "---- STO IN add_cmd riga 297 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        return cmd_cache.insert(std::make_pair(cmd->get_hash(), cmd)).first->second;
    }

    command_t find_cmd(const uint256_t &cmd_hash) {
        std::cout << "---- STO IN find_cmd riga 303 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        auto it = cmd_cache.find(cmd_hash);
        return it == cmd_cache.end() ? nullptr: it->second;
    }

    size_t get_cmd_cache_size() {
        return cmd_cache.size();
    }
    size_t get_blk_cache_size() {
        return blk_cache.size();
    }

    bool try_release_cmd(const command_t &cmd) {
        std::cout << "---- STO IN try_release_cmd riga 317 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        if (cmd.get_cnt() == 2) /* only referred by cmd and the storage */
        {
            const auto &cmd_hash = cmd->get_hash();
            cmd_cache.erase(cmd_hash);
            return true;
        }
        return false;
    }

    bool try_release_blk(const block_t &blk) {
        std::cout << "---- STO IN try_release_blk riga 329 DENTRO entity.h package:include->hotstuff---- " << std::endl;

        if (blk.get_cnt() == 2) /* only referred by blk and the storage */
        {
            const auto &blk_hash = blk->get_hash();
#ifdef HOTSTUFF_PROTO_LOG
            HOTSTUFF_LOG_INFO("releasing blk %.10s", get_hex(blk_hash).c_str());
#endif
//            for (const auto &cmd: blk->get_cmds())
//                try_release_cmd(cmd);
            blk_cache.erase(blk_hash);
            return true;
        }
#ifdef HOTSTUFF_PROTO_LOG
        else
            HOTSTUFF_LOG_INFO("cannot release (%lu)", blk.get_cnt());
#endif
        return false;
    }
};

}

#endif
