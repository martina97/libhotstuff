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

#ifndef _HOTSTUFF_CONSENSUS_H
#define _HOTSTUFF_CONSENSUS_H

#include <cassert>
#include <set>
#include <unordered_map>
#include <map>

#include "hotstuff/promise.hpp"
#include "hotstuff/type.h"
#include "hotstuff/entity.h"
#include "hotstuff/crypto.h"
#include "secp256k1_frost.h"

#define EXAMPLE_MAX_PARTICIPANTS 4
namespace hotstuff {

struct Proposal;
struct Vote;
struct Finality;

/** Abstraction for HotStuff protocol state machine (without network implementation). */
class HotStuffCore {
    block_t b0;                                  /** the genesis block */
    /* === state variables === */
    /** block containing the QC for the highest block having one */
    std::pair<block_t, quorum_cert_bt> hqc;   /**< highest QC */
    block_t b_lock;                            /**< locked block */
    block_t b_exec;                            /**< last executed block */
    uint32_t vheight;          /**< height of the block last voted for */
    /* === auxilliary variables === */
    privkey_bt priv_key;            /**< private key for signing votes */
    std::set<block_t> tails;   /**< set of tail blocks */
    ReplicaConfig config;                   /**< replica configuration */
    /* === async event queues === */
    std::unordered_map<block_t, promise_t> qc_waiting;
    promise_t propose_waiting;
    promise_t receive_proposal_waiting;
    promise_t hqc_update_waiting;
    secp256k1_frost_keypair *key_pair;
    std::map<std::string, std::list<secp256k1_frost_nonce_commitment>> commitment_map;
    // Define a mutex to protect access to commitment_map
    std::mutex map_mutex;
    //secp256k1_frost_signature_share *signature_share;
    /* == feature switches == */
    /** always vote negatively, useful for some PaceMakers */
    bool vote_disabled;
    secp256k1_context *sign_verify_ctx;
    std::vector<secp256k1_frost_nonce*> nonce_list;    // i nonce-commitment della replica ! (non degli altri)
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    block_t get_delivered_blk(const uint256_t &blk_hash);
    void sanity_check_delivered(const block_t &blk);
    void update(const block_t &nblk);
    void update_hqc(const block_t &_hqc, const quorum_cert_bt &qc);
    void on_hqc_update();
    void on_qc_finish(const block_t &blk);
    void on_propose_(const Proposal &prop);
    void on_receive_proposal_(const Proposal &prop);

    protected:
    ReplicaID id;                  /**< identity of the replica itself */

    public:
    BoxObj<EntityStorage> storage;

    HotStuffCore(ReplicaID id, privkey_bt &&priv_key);
    virtual ~HotStuffCore() {
        std::cout << "---- STO IN HotStuffCore riga 73 DENTRO consensus.h package:include->hotstuff---- " << std::endl;
        b0->qc_ref = nullptr;
    }

    /* Inputs of the state machine triggered by external events, should called
     * by the class user, with proper invariants. */

    /** Call to initialize the protocol, should be called once before all other
     * functions. */
    void on_init(uint32_t nfaulty);

    /* TODO: better name for "delivery" ? */
    /** Call to inform the state machine that a block is ready to be handled.
     * A block is only delivered if itself is fetched, the block for the
     * contained qc is fetched and all parents are delivered. The user should
     * always ensure this invariant. The invalid blocks will be dropped by this
     * function.
     * @return true if valid */
    bool on_deliver_blk(const block_t &blk);

    /** Call upon the delivery of a proposal message.
     * The block mentioned in the message should be already delivered. */
    void on_receive_proposal(const Proposal &prop);

    /** Call upon the delivery of a vote message.
     * The block mentioned in the message should be already delivered. */
    void on_receive_vote(const Vote &vote);

    /** Call to submit new commands to be decided (executed). "Parents" must
     * contain at least one block, and the first block is the actual parent,
     * while the others are uncles/aunts */
    block_t on_propose(const std::vector<uint256_t> &cmds,
                    const std::vector<block_t> &parents,
                    bytearray_t &&extra = bytearray_t());

    /* Functions required to construct concrete instances for abstract classes.
     * */

    /* Outputs of the state machine triggering external events.  The virtual
     * functions should be implemented by the user to specify the behavior upon
     * the events. */
    protected:
    /** Called by HotStuffCore upon the decision being made for cmd. */
    virtual void do_decide(Finality &&fin) = 0;
    virtual void do_consensus(const block_t &blk) = 0;

    /** Called by HotStuffCore upon broadcasting a new proposal.
     * The user should send the proposal message to all replicas except for
     * itself. */
    virtual void do_broadcast_proposal(const Proposal &prop) = 0;
    /** Called upon sending out a new vote to the next proposer.  The user
     * should send the vote message to a *good* proposer to have good liveness,
     * while safety is always guaranteed by HotStuffCore. */
    virtual void do_vote(ReplicaID last_proposer, const Vote &vote) = 0;

    /* The user plugs in the detailed instances for those
     * polymorphic data types. */
    public:
    /** Create a partial certificate that proves the vote for a block. */
    virtual part_cert_bt create_part_cert(const PrivKey &priv_key, const uint256_t &blk_hash) = 0;
    /** Create a partial certificate from its seralized form. */
    virtual part_cert_bt parse_part_cert(DataStream &s) = 0;
    /** Create a quorum certificate that proves 2f+1 votes for a block. */
    virtual quorum_cert_bt create_quorum_cert(const uint256_t &blk_hash, bool frost) = 0;
    /** Create a quorum certificate from its serialized form. */
    virtual quorum_cert_bt parse_quorum_cert(DataStream &s) = 0;
    /** Create a command object from its serialized form. */
    //virtual command_t parse_cmd(DataStream &s) = 0;

    public:
    /** Add a replica to the current configuration. This should only be called
     * before running HotStuffCore protocol. */
    void add_replica(ReplicaID rid, const PeerId &peer_id, pubkey_bt &&pub_key);
    void add_replica_frost(ReplicaID rid, const PeerId &peer_id, hotstuff::PubKeyFrost &pub_key);
    /** Try to prune blocks lower than last committed height - staleness. */
    void prune(uint32_t staleness);

    /* PaceMaker can use these functions to monitor the core protocol state
     * transition */
    /** Get a promise resolved when the block gets a QC. */
    promise_t async_qc_finish(const block_t &blk);
    /** Get a promise resolved when a new block is proposed. */
    promise_t async_wait_proposal();
    /** Get a promise resolved when a new proposal is received. */
    promise_t async_wait_receive_proposal();
    /** Get a promise resolved when hqc is updated. */
    promise_t async_hqc_update();

    /* Other useful functions */
    const block_t &get_genesis() const { return b0; }
    const block_t &get_hqc() { return hqc.first; }
    const ReplicaConfig &get_config() const { return config; }
    ReplicaID get_id() const { return id; }
    const std::set<block_t> get_tails() const { return tails; }
    operator std::string () const;
    void set_vote_disabled(bool f) { vote_disabled = f; }

    void add_keypair_frost(ReplicaID rid, PubKeyFrost &pub_key);
};

/** Abstraction for proposal messages. */
struct Proposal: public Serializable {
    bool frost{};
    ReplicaID proposer;
    /** block being proposed */
    block_t blk;
    /** handle of the core object to allow polymorphism. The user should use
     * a pointer to the object of the class derived from HotStuffCore */
    HotStuffCore *hsc;
    std::list<secp256k1_frost_nonce_commitment> *commitment_list;

    Proposal(): blk(nullptr), hsc(nullptr) {}
    Proposal(bool frost,ReplicaID proposer,
            const block_t &blk,
            HotStuffCore *hsc):
            frost(frost),
            proposer(proposer),
            blk(blk), hsc(hsc) {}

    void serialize(DataStream &s) const override {

        std::cout << "---- STO IN serialize riga 204 DENTRO consensus.h package:include->hotstuff---- " << std::endl;
        std::cout << "s == " << s.get_hex() << std::endl;
        s<<frost;
        s << proposer;


        if (frost == 1) {
            // Serialize the size of the commitment_list
            uint32_t commitmentListSize = commitment_list ? commitment_list->size() : 0;
            s << commitmentListSize;


            // Serialize each commitment in the list
            if (commitment_list) {
                for (const auto &commitment : *commitment_list) {
                    s << commitment.index; // Serialize the index
                    for (int i = 0; i < 64; ++i) {
                        s << commitment.hiding[i]; // Serialize hiding array
                    }
                    for (int i = 0; i < 64; ++i) {
                        s << commitment.binding[i]; // Serialize binding array
                    }
                }
            }
        }

        s  << *blk;

        // Serialize the size of the commitment_list



        std::cout << "s == " << s.get_hex() << std::endl;

    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 234 DENTRO consensus.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;

        assert(hsc != nullptr);
        s>>frost;
        std::cout << "frost == "  << frost << std::endl;

        s >> proposer;
        // Deserialize the number of commitments in the list

        if (frost == 1) {
            uint32_t num_commitments;
            s >> num_commitments;
            std::cout << "dopo num comm --> s == " << s.get_hex() << std::endl;
            // vuol dire che il blocco avrà i commitment list
            // Deserialize each commitment in the list
            commitment_list = new std::list<secp256k1_frost_nonce_commitment>();
            for (uint32_t i = 0; i < num_commitments; ++i) {
                std::cout << "i == " << i << std::endl;
                
                secp256k1_frost_nonce_commitment commitment;
                s >> commitment.index; // Deserialize the index
                std::cout << "s == " << s.get_hex() << std::endl;
                for (int j = 0; j < 64; ++j) {
                    s >> commitment.hiding[j]; // Deserialize hiding array
                }
                for (int j = 0; j < 64; ++j) {
                    s >> commitment.binding[j]; // Deserialize binding array
                }
                commitment_list->push_back(commitment);
            }

        }

        Block _blk;
        _blk.unserialize(s, hsc);
        std::cout << "hsc->get_config().nmajority = " << hsc->get_config().nmajority << std::endl;

        blk = hsc->storage->add_blk(std::move(_blk), hsc->get_config());
        std::cout << "BLOCCO FROST == " << blk->frost << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;



        
    }

    operator std::string () const {
        std::cout << "---- STO IN std::string riga 204 DENTRO consensus.h package:include->hotstuff---- " << std::endl;

        DataStream s;
        s << "<proposal "
          << "rid=" << std::to_string(proposer) << " "
          << "blk=" << get_hex10(blk->get_hash()) << ">";
        return s;
    }
};

/** Abstraction for vote messages. */
struct Vote: public Serializable {
    bool frost{};
    ReplicaID voter{};
    /** block being voted */
    uint256_t blk_hash;
    /** proof of validity for the vote */
    part_cert_bt cert;

    secp256k1_frost_nonce_commitment *commitment{}; //il voto trasporta i commitment generati dal voter
    /** handle of the core object to allow polymorphism */
    HotStuffCore *hsc;

   // PartCertFrost *cert_frost;

    Vote(): cert(nullptr), hsc(nullptr) {}

    Vote(bool frost, ReplicaID voter, const uint256_t &blk_hash, part_cert_bt &&cert,
         secp256k1_frost_nonce_commitment *commitment, HotStuffCore *hsc):
        frost(frost),
        voter(voter),
        blk_hash(blk_hash),
        cert(std::move(cert)), commitment(commitment),hsc(hsc) {}

        /*
    Vote(ReplicaID voter,
         const uint256_t &blk_hash,
         hotstuff::PartCertFrost &cert, secp256k1_frost_nonce_commitment *commitment,
         HotStuffCore *hsc):
            voter(voter),
            blk_hash(blk_hash),
            cert_frost(&cert), commitment(commitment), hsc(hsc) {}*/
    Vote(bool frost, ReplicaID voter,
         const uint256_t &blk_hash, secp256k1_frost_nonce_commitment *commitment,
         HotStuffCore *hsc):
            frost(frost),
            voter(voter),
            blk_hash(blk_hash),
            commitment(commitment), hsc(hsc){}

    Vote(const Vote &other):
        frost(other.frost),
        voter(other.voter),
        blk_hash(other.blk_hash),
        cert(other.cert ? other.cert->clone() : nullptr),
        hsc(other.hsc),
        commitment(other.commitment) {}

    Vote(Vote &&other) = default;
    
    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 244 DENTRO consensus.h package:include->hotstuff---- " << std::endl;
        s << frost;
        s << voter << blk_hash ;

        // Serialize cert_frost and commitment if frost is true
        //s << *cert_frost;
        //s << static_cast<uint32_t>(commitment->index);
        std::cout << "commitment index == " << commitment->index << std::endl;
        s << commitment->index;
        //s << htole(commitment->index);
        for (unsigned char i : commitment->hiding) {
            s << i;

        }
        for (unsigned char i : commitment->binding) {
            s << i;
        }
        // Assuming commitment is not nullptr, serialize it
        //s << *commitment;
        s << *cert;

    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 250 DENTRO consensus.h package:include->hotstuff---- " << std::endl;

        std::cout << s.get_hex() << std::endl;
        s >> frost;
        assert(hsc != nullptr);
        s >> voter >> blk_hash;

       // s<<frost;
        std::cout << "frost == " << frost << std::endl;
        std::cout << "voter == " << voter << std::endl;
        std::cout << "blk_hash == " << blk_hash.to_hex() << std::endl;


        //s>>frost;

        //if(frost) todo
        // Deserialize cert_frost and commitment if frost is true
       // cert_frost = new PartCertFrost();
        //s >> *cert_frost;
        /*
        unsigned char discard2;
        s<<discard2;
        s<<discard2;
        s<<discard2;
         */
        // Allocate memory for commitment
        commitment = new secp256k1_frost_nonce_commitment();
        s >> commitment->index; // Deserialize index as uint32_t

        std::cout << "commitment index == " << commitment->index << std::endl;

        //= static_cast<uint32_t>(letoh(index)); // Convert to host byte order

        // Convert to host byte order

        // Skip the first two bytes before reading hiding and binding arrays
        // Discard the first two values from the stream
        /*
        unsigned char discard1;
        s >> discard1 ;
         */

        // Deserialize commitment fields individually
        for (int i = 0; i < 64; ++i) {
            s >> commitment->hiding[i];
        }
        for (int i = 0; i < 64; ++i) {
            s >> commitment->binding[i];
        }
        //s << discard1 << discard1;
        cert = hsc->parse_part_cert(s);


    }

    bool verify() const {
        std::cout << "---- STO IN verify riga 259 DENTRO consensus.h package:include->hotstuff---- " << std::endl;

        assert(hsc != nullptr);
        return cert->verify(hsc->get_config().get_pubkey(voter)) &&
                cert->get_obj_hash() == blk_hash;
    }

    promise_t verify(VeriPool &vpool) const {
        std::cout << "---- STO IN verify riga 267 DENTRO consensus.h package:include->hotstuff---- " << std::endl;

        assert(hsc != nullptr);
        std::cout << cert->to_hex() << std::endl;
        std::cout << cert->get_obj_hash().to_hex() << std::endl;
        std::cout << blk_hash.to_hex() << std::endl;
        return cert->verify(hsc->get_config().get_pubkey(voter), vpool).then([this](bool result) {
        //return cert->verify(hsc->get_config().get_pubkey_frost(voter), vpool).then([this](bool result) {
            return result && cert->get_obj_hash() == blk_hash;
        });

    }

    operator std::string () const {
        std::cout << "---- STO IN std::string riga 275 DENTRO consensus.h package:include->hotstuff---- " << std::endl;

        DataStream s;
        s << "<vote "
          << "rid=" << std::to_string(voter) << " "
          << "blk=" << get_hex10(blk_hash) << ">";
        return s;
    }
};

struct Finality: public Serializable {
    ReplicaID rid;
    int8_t decision;
    uint32_t cmd_idx;
    uint32_t cmd_height;
    uint256_t cmd_hash;
    uint256_t blk_hash;
    
    public:
    Finality() = default;
    Finality(ReplicaID rid,
            int8_t decision,
            uint32_t cmd_idx,
            uint32_t cmd_height,
            uint256_t cmd_hash,
            uint256_t blk_hash):
        rid(rid), decision(decision),
        cmd_idx(cmd_idx), cmd_height(cmd_height),
        cmd_hash(cmd_hash), blk_hash(blk_hash) {}

    void serialize(DataStream &s) const override {
        s << rid << decision
          << cmd_idx << cmd_height
          << cmd_hash;
        if (decision == 1) s << blk_hash;
    }

    void unserialize(DataStream &s) override {
        s >> rid >> decision
          >> cmd_idx >> cmd_height
          >> cmd_hash;
        if (decision == 1) s >> blk_hash;
    }

    operator std::string () const {
        DataStream s;
        s << "<fin "
          << "decision=" << std::to_string(decision) << " "
          << "cmd_idx=" << std::to_string(cmd_idx) << " "
          << "cmd_height=" << std::to_string(cmd_height) << " "
          << "cmd=" << get_hex10(cmd_hash) << " "
          << "blk=" << get_hex10(blk_hash) << ">";
        return s;
    }
};

}

#endif
