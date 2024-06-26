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

#ifndef _HOTSTUFF_CRYPTO_H
#define _HOTSTUFF_CRYPTO_H

#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <map>
#include <utility>

#include "secp256k1.h"
#include "secp256k1_frost.h"
#include "salticidae/crypto.h"
#include "hotstuff/type.h"
#include "hotstuff/task.h"
#include "eckey_impl.h"
//#include "../secp256k1-frost/src/modules/frost/main_impl.h"
namespace hotstuff {

using salticidae::SHA256;

class PubKey: public Serializable, Cloneable {
    public:
    virtual ~PubKey() = default;
    virtual PubKey *clone() override = 0;
};

using pubkey_bt = BoxObj<PubKey>;
class PartCertFrost;
class PrivKey: public Serializable {
    public:
    virtual ~PrivKey() = default;
    virtual pubkey_bt get_pubkey() const = 0;
    virtual void from_rand() = 0;
};

using privkey_bt = BoxObj<PrivKey>;

class PartCert: public Serializable, public Cloneable {
    public:
    virtual ~PartCert() = default;
    virtual promise_t verify(const PubKey &pubkey, VeriPool &vpool) = 0;
    virtual bool verify(const PubKey &pubkey) = 0;
    virtual const uint256_t &get_obj_hash() const = 0;
    virtual PartCert *clone() override = 0;
};

class ReplicaConfig;

class QuorumCert: public Serializable, public Cloneable {
    public:
    virtual ~QuorumCert() = default;
    virtual void add_part(ReplicaID replica, const PartCert &pc) = 0;
    virtual void add_part(ReplicaID replica, const PartCertFrost &pc) = 0;
    virtual salticidae::Bits getRids() = 0;
    virtual std::map<ReplicaID, secp256k1_frost_signature_share> get_sigs_frost() = 0;
    virtual std::list<ReplicaID> get_index_voters()=0;
    virtual void compute(const uint256_t msg_hash, const secp256k1_frost_keypair *keypair, secp256k1_frost_pubkey *public_keys, std::list<secp256k1_frost_nonce_commitment> commit_list) = 0;
    virtual void compute() = 0;
    virtual promise_t verify(const ReplicaConfig &config, VeriPool &vpool) = 0;
    virtual bool verify(const ReplicaConfig &config) = 0;
    virtual const uint256_t &get_obj_hash() const = 0;
    virtual QuorumCert *clone() override = 0;
};

using part_cert_bt = BoxObj<PartCert>;
using quorum_cert_bt = BoxObj<QuorumCert>;

class PubKeyDummy: public PubKey {
    PubKeyDummy *clone() override { return new PubKeyDummy(*this); }
    void serialize(DataStream &) const override {}
    void unserialize(DataStream &) override {}
};

class PrivKeyDummy: public PrivKey {
    pubkey_bt get_pubkey() const override { return new PubKeyDummy(); }
    void serialize(DataStream &) const override {}
    void unserialize(DataStream &) override {}
    void from_rand() override {}
};

class PartCertDummy: public PartCert {
        
    uint256_t obj_hash;
    public:
    PartCertDummy() {std::cout << "partCertDummy2" << std::endl;}
    PartCertDummy(const uint256_t &obj_hash):
        obj_hash(obj_hash) {std::cout << "partCertDummy" << std::endl;
        }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 96 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        s << (uint32_t)0 << obj_hash;
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 102 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        uint32_t tmp;
        s >> tmp >> obj_hash;
    }

    PartCert *clone() override {
        std::cout << "---- STO IN clone riga 109 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        return new PartCertDummy(obj_hash);
    }

    bool verify(const PubKey &) override {
        std::cout << "---- STO IN verify riga 114 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        return true;
    }
    promise_t verify(const PubKey &, VeriPool &) override {
        std::cout << "---- STO IN verify riga 118 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        return promise_t([](promise_t &pm){ pm.resolve(true); });
    }

    const uint256_t &get_obj_hash() const override {
        std::cout << "---- STO IN get_obj_hash riga 123 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        return obj_hash; 
    }
};

class QuorumCertDummy: public QuorumCert {
    uint256_t obj_hash;
    public:
    QuorumCertDummy() {}
    QuorumCertDummy(const ReplicaConfig &, const uint256_t &obj_hash):
        obj_hash(obj_hash) {}

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 136 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        s << (uint32_t)1 << obj_hash;
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 142 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        uint32_t tmp;
        s >> tmp >> obj_hash;
    }

    QuorumCert *clone() override {
        std::cout << "---- STO IN clone riga 149 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        return new QuorumCertDummy(*this);
    }

    void add_part(ReplicaID, const PartCert &) override {}
    void add_part(ReplicaID, const PartCertFrost &) override {}
    salticidae::Bits getRids() override {}
    std::map<ReplicaID, secp256k1_frost_signature_share> get_sigs_frost() override {}
    std::list<ReplicaID> get_index_voters() override {}
    void compute(const uint256_t blob, const secp256k1_frost_keypair *keypair,secp256k1_frost_pubkey *public_keys,std::list<secp256k1_frost_nonce_commitment> commit_list) override {}
    void compute() override {}
    bool verify(const ReplicaConfig &) override { return true; }
    promise_t verify(const ReplicaConfig &, VeriPool &) override {
        std::cout << "---- STO IN verify riga 158 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        return promise_t([](promise_t &pm) { pm.resolve(true); });
    }

    const uint256_t &get_obj_hash() const override {
        std::cout << "---- STO IN get_obj_hash riga 164 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        return obj_hash; }
};



class Secp256k1Context {
    secp256k1_context *ctx;
    friend class PubKeySecp256k1;
    friend class PubKeySecp256k1Frost;
    friend class SigSecp256k1;
    public:
    Secp256k1Context(bool sign = false):
        ctx(secp256k1_context_create(
            sign ? SECP256K1_CONTEXT_SIGN :
                    SECP256K1_CONTEXT_VERIFY)) {std::cout << "---- STO IN Secp256k1Context riga 176 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
    }

    Secp256k1Context(const Secp256k1Context &) = delete;

    Secp256k1Context(Secp256k1Context &&other): ctx(other.ctx) {
        std::cout << "---- STO IN Secp256k1Context riga 184 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        other.ctx = nullptr;
    }

    ~Secp256k1Context() {
        if (ctx) secp256k1_context_destroy(ctx);
    }
};

using secp256k1_context_t = ArcObj<Secp256k1Context>;

extern secp256k1_context_t secp256k1_default_sign_ctx;
extern secp256k1_context_t secp256k1_default_verify_ctx;

class PrivKeySecp256k1;

class PubKeySecp256k1: public PubKey {
    static const auto _olen = 33;
    friend class SigSecp256k1;
    secp256k1_pubkey data;
    secp256k1_context_t ctx;

    public:
    PubKeySecp256k1(const secp256k1_context_t &ctx = secp256k1_default_sign_ctx):
        PubKey(), ctx(ctx) {
            std::cout << "---- STO IN PubKeySecp256k1 RIGA 213---- " << std::endl;
        }
    
    PubKeySecp256k1(const bytearray_t &raw_bytes,
                    const secp256k1_context_t &ctx =
                            secp256k1_default_sign_ctx):
        PubKeySecp256k1(ctx) {
        std::cout << "---- STO IN PubKeySecp256k1 RIGA 218---- " << std::endl;
        from_bytes(raw_bytes); }



    inline PubKeySecp256k1(const PrivKeySecp256k1 &priv_key,
                            const secp256k1_context_t &ctx =
                                    secp256k1_default_sign_ctx);

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 222 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        static uint8_t output[_olen];
        size_t olen = _olen;
        (void)secp256k1_ec_pubkey_serialize(
                ctx->ctx, (unsigned char *)output,
                &olen, &data, SECP256K1_EC_COMPRESSED);
        s.put_data(output, output + _olen);
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 233 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        //printf("ciaoooo cacca");
        static const auto _exc = std::invalid_argument("ill-formed public key");
        try {
            std::cout << "sto dopo secp256k1_ec_pubkey_parse" << std::endl;
            int boh = secp256k1_ec_pubkey_parse(ctx->ctx, &data, s.get_data_inplace(_olen), _olen);
            if (!boh) {
                throw _exc;
            }
                
        } catch (std::ios_base::failure &) {
            throw _exc;
        }
    }

    PubKeySecp256k1 *clone() override {
        std::cout << "---- STO IN clone riga 246 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        return new PubKeySecp256k1(*this);
    }
};

class PubKeySecp256k1Frost: public PubKey {
    static const auto _olen = 64;
    friend class SigSecp256k1;
    secp256k1_frost_pubkey data;
    secp256k1_context_t ctx;


    public:
    PubKeySecp256k1Frost(secp256k1_context_t ctx =
    secp256k1_default_sign_ctx):
            PubKey(), ctx(std::move(ctx)) {std::cout << "---- STO IN PubKeySecp256k1Frost riga 267 ---- " << std::endl;}

    PubKeySecp256k1Frost(const bytearray_t &raw_bytes,
                    const secp256k1_context_t &ctx =
                    secp256k1_default_sign_ctx):
        PubKeySecp256k1Frost(ctx) {
        // Copy the combined key to the data structure
        if (raw_bytes.size() != (sizeof(data.public_key) + sizeof(data.group_public_key))) {
            throw std::invalid_argument("Invalid combined key size");
        }
        std::cout << "---- STO IN PubKeySecp256k1Frost riga 270---- " << std::endl;
        std::copy(raw_bytes.begin(), raw_bytes.begin() + 64, data.public_key);
        std::copy(raw_bytes.begin() + 64, raw_bytes.end(), data.group_public_key);

        std::cout << "provo a stampare dentro costruttore" << std::endl;
        
        auto pub = data.public_key;
        for (size_t i = 0; i < 64; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pub[i]);
        }
        std::cout << std::endl;

        auto pub2 = data.group_public_key;
        for (size_t i = 0; i < 64; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pub2[i]);
        }
        std::cout << std::endl;
        //std::cout << salticidae::get_hex(data.public_key)<< std::endl;

        from_bytes(raw_bytes) ;    }


    // Constructor to initialize with public key and group public key
    PubKeySecp256k1Frost(const std::vector<uint8_t> &public_key,
                         const std::vector<uint8_t> &group_public_key,
                         const secp256k1_context_t &ctx = secp256k1_default_sign_ctx):
            PubKeySecp256k1Frost(ctx) {
        std::cout << "--- STO IN PubKeySecp256k1Frost riga riga 278----" << std::endl;
        
        // Copy the public key and group public key to the data structure
        std::copy(public_key.begin(), public_key.end(), data.public_key);
        std::copy(group_public_key.begin(), group_public_key.end(), data.group_public_key);
    }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize linea 275 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        static uint8_t output[2*_olen];
        size_t olen = _olen;
        // Convert the public key to secp256k1_pubkey
        secp256k1_pubkey pub_key;
        secp256k1_ec_pubkey_parse(ctx->ctx, &pub_key, data.public_key, sizeof(data.public_key));

        // Serialize public_key
        (void)secp256k1_ec_pubkey_serialize(
                ctx->ctx, (unsigned char *)output,
                &olen, &pub_key, SECP256K1_EC_COMPRESSED);

        // Convert the group public key to secp256k1_pubkey
        secp256k1_pubkey group_pub_key;
        secp256k1_ec_pubkey_parse(ctx->ctx, &group_pub_key, data.group_public_key, sizeof(data.group_public_key));

        // Serialize group_public_key
        (void)secp256k1_ec_pubkey_serialize(
                ctx->ctx, (unsigned char *)(output + 64),
                &olen, &group_pub_key, SECP256K1_EC_COMPRESSED);

        //s.put_data(output, output + _olen);
        s.put_data(output, output + 2 * _olen);
    }
    
    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 300 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        std::cout << s.get_hex() << std::endl;

        static const auto _exc = std::invalid_argument("ill-formed public key");
        static const auto _exc2 = std::invalid_argument("ill-formed group public key");

        const unsigned char *boh = s.get_data_inplace(_olen);
        for (size_t i = 0; i < _olen; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(boh[i]);
        }
        std::cout << std::endl;
        
        try {
            std::cout << "PRIMO TRY" << std::endl;

            // Parse the serialized data for public key
            secp256k1_pubkey pub_key;
            if (!secp256k1_ec_pubkey_parse(ctx->ctx, &pub_key, s.get_data_inplace(_olen), _olen)) {
                std::cout << "CASO 1" << std::endl;
                throw _exc;
            }
            std::cout << "dopo try" << std::endl;
            // Copy the parsed public key to the data
            //memcpy(data.public_key, pub_key.data, sizeof(data.public_key));
            std::cout << "sto quaaaa" << std::endl;

            /*
            std::cout << "secondo TRY" << std::endl;
            std::cout << "AOOOOOOOOOOOOOOOOOOOOOOOO" << std::endl;
            std::cout << "AOOOOOOOOOOOOOOOOOOOOOOOO" << std::endl;

            const unsigned char *ee = s.get_data_inplace(_olen);
            for (size_t i = 0; i < _olen; ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(ee[i]);
            }
            std::cout << std::endl;
            // Parse the serialized data for group public key
            secp256k1_pubkey group_pub_key;
            if (!secp256k1_ec_pubkey_parse(ctx->ctx, &group_pub_key, s.get_data_inplace(_olen), _olen)) {
                std::cout << "CASO 2" << std::endl;
                throw _exc2;
            }
            // Copy the parsed group public key to the data
             */
            //memcpy(data.group_public_key, group_pub_key.data, sizeof(data.group_public_key));
        } catch (std::ios_base::failure &) {
            throw _exc2;
        }

    }
    

    PubKeySecp256k1Frost *clone() override {
        return new PubKeySecp256k1Frost(*this);
    }
};

class PartCertFrost: public Serializable {
public:
    std::unique_ptr<secp256k1_frost_signature_share> signature_share;
    uint256_t obj_hash;
    PartCertFrost() = default;

    // Constructor to create a null or empty PartCertFrost
    PartCertFrost(const uint256_t &msg_hash, bool is_null = false) : obj_hash(msg_hash) {
        if (!is_null) {
            // If not null, initialize the signature_share
            signature_share.reset(new secp256k1_frost_signature_share);
        }
    }

    PartCertFrost(const PartCertFrost &other) {
        obj_hash = other.obj_hash;
        signature_share.reset(new secp256k1_frost_signature_share(*other.signature_share));
    }
    PartCertFrost(const uint256_t &msg_hash,
                  uint32_t num_signers,
                  const secp256k1_frost_keypair *keypair,
                  secp256k1_frost_nonce *nonce,
                  secp256k1_frost_nonce_commitment *signing_commitments) {
        std::cout << "sto in PartCertFrost" << std::endl;
        
        obj_hash = msg_hash;
        // Convert uint256_t to unsigned char array
        //const unsigned char *msg_data = reinterpret_cast<const unsigned char*>(msg_hash_.data());

        const bytearray_t &msg = msg_hash.to_bytes();
        (unsigned char *) &*msg.begin();
        signature_share.reset(new secp256k1_frost_signature_share);

        int res = secp256k1_frost_sign(signature_share.get(), (unsigned char *) &*msg.begin(), num_signers, keypair, nonce,
                                       signing_commitments);
        std::cout << "res = " << res << std::endl;
        if (res != 1) {
            const std::basic_string<char, std::char_traits<char>, std::allocator<char>> &s =
                    "Failed to create signature share for " + msg_hash.to_hex();
            //throw std::runtime_error(s);
            HOTSTUFF_LOG_WARN("Failed to create signature share!");
            //signature_share.reset();

        }

    }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 444 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        s << obj_hash;
        // Serialize signature_share if it exists
        bool has_signature_share = (signature_share != nullptr);
        s << has_signature_share;
        if (has_signature_share) {
            // Serialize index
            s << signature_share->index;
            // Serialize response
            s << bytearray_t(signature_share->response, signature_share->response + sizeof(signature_share->response));
        }
        std::cout << "s = " << s.get_hex() << std::endl;
        
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 451 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;
        s >> obj_hash;
        bool has_signature_share;
        s >> has_signature_share;
        if (has_signature_share) {
            signature_share.reset(new secp256k1_frost_signature_share);
            // Unserialize index
            s >> signature_share->index;
            // Unserialize response
            for (unsigned char & i : signature_share->response) {
                s >> i;
            }
        } else {
            signature_share.reset();
        }
    }
};







class PubKeyFrost {
    friend class SigSecp256k1;
    secp256k1_context_t ctx;

public:
    std::unique_ptr<secp256k1_frost_pubkey> data;
    PubKeyFrost(unsigned char *pubkey33, unsigned char *group_pubkey33, const uint32_t index,
                const uint32_t max_participants) { // Constructor with parameters
        std::cout << "sto in PubKeyFrost riga 412 crypto.h" << std::endl;
        std::cout << "index = " << index << std::endl;
        std::cout << "max partecipants = " << max_participants << std::endl;
        
        
        static const auto _exc = std::invalid_argument("ill-formed public key");
        try {
            std::cout << "PRIMO TRY ! " << std::endl;
            data.reset(new secp256k1_frost_pubkey); // Allocating memory for data
            int out = secp256k1_frost_pubkey_load(data.get(), index, max_participants, pubkey33,group_pubkey33);
            std::cout << "out = " <<out << std::endl;
            std::cout << "dopo" << std::endl;

            if (!out) {
                std::cout << "sto in if not out" << std::endl;
                
                throw _exc;
            }
        } catch (std::ios_base::failure &) {
            throw _exc;
        }

    }
    // Member function to serialize the public key and group public key
    const std::pair<std::vector<unsigned char>, std::vector<unsigned char>> serializePubKeys() {
        secp256k1_frost_pubkey* pubkey = data.get();
        std::vector<unsigned char> pubkey33(33);
        std::vector<unsigned char> group_pubkey33(33);

        int result = secp256k1_frost_pubkey_save(&pubkey33[0], &group_pubkey33[0], pubkey);
        if (result != 1) {
            throw std::runtime_error("Failed to serialize public keys");
        }
        return std::make_pair(pubkey33, group_pubkey33);
    }




};



class PrivKeySecp256k1: public PrivKey {
    static const auto nbytes = 32;
    friend class PubKeySecp256k1;
    friend class SigSecp256k1;
    uint8_t data[nbytes];
    secp256k1_context_t ctx;

    public:
    PrivKeySecp256k1(const secp256k1_context_t &ctx =
                            secp256k1_default_sign_ctx):
        PrivKey(), ctx(ctx) {std::cout << "STO IN PrivKeySecp256k1" << std::endl;
        }

    PrivKeySecp256k1(const bytearray_t &raw_bytes,
                     const secp256k1_context_t &ctx =
                            secp256k1_default_sign_ctx):
        PrivKeySecp256k1(ctx) {
        std::cout << "STO IN PrivKeySecp256k1" << std::endl;
        from_bytes(raw_bytes); }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 269 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        s.put_data(data, data + nbytes);
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 274 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        static const auto _exc = std::invalid_argument("ill-formed private key");
        try {
            memmove(data, s.get_data_inplace(nbytes), nbytes);
        } catch (std::ios_base::failure &) {
            throw _exc;
        }
    }

    void from_rand() override {
        std::cout << "---- STO IN from_rand riga 285 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        if (!RAND_bytes(data, nbytes))
            throw std::runtime_error("cannot get rand bytes from openssl");
    }

    inline pubkey_bt get_pubkey() const override;
};

pubkey_bt PrivKeySecp256k1::get_pubkey() const {
    std::cout << "---- STO IN get_pubkey riga 295 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

    return new PubKeySecp256k1(*this, ctx);
}

PubKeySecp256k1::PubKeySecp256k1(

        const PrivKeySecp256k1 &priv_key,
        const secp256k1_context_t &ctx): PubKey(), ctx(ctx) {
    if (!secp256k1_ec_pubkey_create(ctx->ctx, &data, priv_key.data))
        throw std::invalid_argument("invalid secp256k1-hotstuff private key");
}

class SigSecp256k1: public Serializable {

    secp256k1_ecdsa_signature data;
    secp256k1_context_t ctx;

    static void check_msg_length(const bytearray_t &msg) {
        std::cout << "---- STO IN check_msg_length riga 315 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        if (msg.size() != 32)
            throw std::invalid_argument("the message should be 32-bytes");
    }

    public:
    SigSecp256k1(const secp256k1_context_t &ctx =
                        secp256k1_default_sign_ctx):
        Serializable(), ctx(ctx) {}
    SigSecp256k1(const uint256_t &digest,const PrivKeySecp256k1 &priv_key, secp256k1_context_t &ctx = secp256k1_default_sign_ctx):
        Serializable(), ctx(ctx) {
        std::cout << "---- STO IN SigSecp256k1 riga 325 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        sign(digest, priv_key);
        std::cout << "---- STO DOPO sign riga 333 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
    }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 339 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        static uint8_t output[64];
        (void)secp256k1_ecdsa_signature_serialize_compact(

            ctx->ctx, (unsigned char *)output,
            &data);
        s.put_data(output, output + 64);
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 350 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        static const auto _exc = std::invalid_argument("ill-formed signature");
        try {
            if (!secp256k1_ecdsa_signature_parse_compact(
                    ctx->ctx, &data, s.get_data_inplace(64)))
                throw _exc;
        } catch (std::ios_base::failure &) {
            throw _exc;
        }
    }

    void sign(const bytearray_t &msg, const PrivKeySecp256k1 &priv_key) {
        std::cout << "---- STO IN sign riga 363 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        check_msg_length(msg);
        if (!secp256k1_ecdsa_sign(
                ctx->ctx, &data,
                (unsigned char *)&*msg.begin(),
                (unsigned char *)priv_key.data,
                NULL, // default nonce function
                NULL))
            throw std::invalid_argument("failed to create secp256k1-hotstuff signature");
    }

    bool verify(const bytearray_t &msg, const PubKeySecp256k1 &pub_key,const secp256k1_context_t &_ctx) const {
        std::cout << "---- STO IN verify riga 376 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        check_msg_length(msg);


        std::cout << "provo stampa key " << pub_key.to_hex() << std::endl;

        for (std::size_t i = 0; i < 33; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data.data[i]);
        }
        std::cout << std::endl;

        for (std::size_t i = 0; i < 33; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pub_key.data.data[i]);
        }
        std::cout << std::endl;

        
        
        bool ret_ecdsa_verify = secp256k1_ecdsa_verify(
                _ctx->ctx, &data,
                (unsigned char *) &*msg.begin(),
                &pub_key.data) == 1;
        std::cout << "ret_ecdsa == " << ret_ecdsa_verify << std::endl;
        
        return ret_ecdsa_verify;
    }

    bool verify(const bytearray_t &msg, const PubKeySecp256k1 &pub_key) {
        std::cout << "---- STO IN verify riga 387 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        return verify(msg, pub_key, ctx);
    }
};

class Secp256k1VeriTask: public VeriTask {
    uint256_t msg;
    PubKeySecp256k1 pubkey;
    SigSecp256k1 sig;
    public:
    Secp256k1VeriTask(const uint256_t &msg,
                        const PubKeySecp256k1 &pubkey,
                        const SigSecp256k1 &sig):
        msg(msg), pubkey(pubkey), sig(sig) {std::cout << "---- STO IN Secp256k1VeriTask riga 393 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
    }
    virtual ~Secp256k1VeriTask() = default;

    bool verify() override {
        std::cout << "---- STO IN verify riga 405 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        std::cout << "provo stampa key " << pubkey.to_hex() << std::endl;
        bool ret = sig.verify(msg, pubkey, secp256k1_default_verify_ctx);
        std::cout << "ret === " << ret << std::endl;

        return ret;
    }
};

class PartCertSecp256k1: public SigSecp256k1, public PartCert {
    uint256_t obj_hash;

    public:
    PartCertSecp256k1() = default;
    PartCertSecp256k1(const PrivKeySecp256k1 &priv_key, const uint256_t &obj_hash):
        SigSecp256k1(obj_hash, priv_key),
        PartCert() ,
        obj_hash(obj_hash) {std::cout << "---- STO IN PartCertSecp256k1 riga 410 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
    }

    bool verify(const PubKey &pub_key) override {
        std::cout << "---- STO IN verify riga 416 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        
        return SigSecp256k1::verify(obj_hash,
                                    static_cast<const PubKeySecp256k1 &>(pub_key),
                                    secp256k1_default_verify_ctx);
    }

    promise_t verify(const PubKey &pub_key, VeriPool &vpool) override {
        std::cout << "---- STO IN verify riga 431 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        std::cout << "provo stampa key " << pub_key.to_hex() << std::endl;
        
        return vpool.verify(new Secp256k1VeriTask(obj_hash,
                static_cast<const PubKeySecp256k1 &>(pub_key),
                static_cast<const SigSecp256k1 &>(*this)));
    }

    const uint256_t &get_obj_hash() const override {
        std::cout << "---- STO IN get_obj_hash riga 439 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        
        return obj_hash; 
    }

    PartCertSecp256k1 *clone() override {
        std::cout << "---- STO IN CLONE riga 445 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        
        return new PartCertSecp256k1(*this);
    }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 451 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        
        s << obj_hash;
        this->SigSecp256k1::serialize(s);
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 458 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        s >> obj_hash;
        this->SigSecp256k1::unserialize(s);
    }
};

class QuorumCertFrost: public QuorumCert {

    public:
    uint256_t obj_hash;
    salticidae::Bits rids;
    bool frost{};
    std::unordered_map<ReplicaID, SigSecp256k1> sigs;
    std::map<ReplicaID, secp256k1_frost_signature_share> sigs_frost;
    unsigned char signature[64];    // firma aggregata
    QuorumCertFrost() = default;
    QuorumCertFrost(const ReplicaConfig &config, const uint256_t &obj_hash, bool frost);
    QuorumCertFrost(uint256_t obj_hash,salticidae::Bits rids, std::map<ReplicaID, secp256k1_frost_signature_share>  sigs_frost) {
        this->sigs_frost =std::move(sigs_frost);
        this->obj_hash = std::move(obj_hash);
    }

    salticidae::Bits getRids() {
        return rids;
    }

    void aggrego(secp256k1_context *sign_verify_ctx, unsigned char *signature, unsigned char *msg,
                                  secp256k1_frost_keypair *key_pair, secp256k1_frost_pubkey *pk,
                                  secp256k1_frost_nonce_commitment *commitments_vec,
                                  const secp256k1_frost_signature_share *signature_shares_vec,
                                  int num_signers) {
        std::cout << "sto in aggregoooooo" << std::endl;
        
        int res = secp256k1_frost_aggregate(sign_verify_ctx, signature,msg,
                                                   key_pair, pk, commitments_vec,
                                                   signature_shares_vec, num_signers);

        std::cout << "res = " << res << std::endl;
        for (uint32_t j = 0; j < 3; ++j) {
            std::cout << "Index at position " << j << ": " << signature_shares_vec[j].index << std::endl;
        }
        std::cout << ".----" << std::endl;
        
        for (uint32_t j = 0; j < 3; ++j) {
            std::cout << "Index at position " << j << ": " << commitments_vec[j].index << std::endl;
        }
        
    }



    std::map<ReplicaID, secp256k1_frost_signature_share> get_sigs_frost() {
        return sigs_frost;
    }
    void add_part(ReplicaID rid, const PartCert &pc) override {
        std::cout << "---- STO IN add_part riga 736 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        if (pc.get_obj_hash() != obj_hash)
            throw std::invalid_argument("PartCert does match the block hash");
        sigs.insert(std::make_pair(
                rid, static_cast<const PartCertSecp256k1 &>(pc)));
        rids.set(rid);
    }

    void add_part(ReplicaID rid, const PartCertFrost &pc) override {
        std::cout << "---- STO IN add_part riga QuorumCertFrost 784 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        std::cout << "pc.obj_hash.to_hex() = " << pc.obj_hash.to_hex() << std::endl;
        std::cout << "obj_hash.to_hex() = " << obj_hash.to_hex() << std::endl;

        if (pc.obj_hash != obj_hash)
            throw std::invalid_argument("PartCertFrost does match the block hash");

        // Insert the signature share into the map
        sigs_frost.emplace(rid, *pc.signature_share);
        rids.set(rid);
        // DEVO AGGIUNGERE ANCHE LA CHIAVE PUB DEL VOTER ALLA LISTA PERCHE MI SERVE PER AGGREGAZIONE
    }

    std::list<ReplicaID> get_index_voters() {
        std::list<ReplicaID> replica_ids;
        for (const auto& entry : sigs_frost) {
            replica_ids.push_back(entry.first);
        }
        return replica_ids;
    }




    // TODO: FARE VERIFY
    void compute(const uint256_t msg_hash, const secp256k1_frost_keypair *keypair,secp256k1_frost_pubkey *public_keys,
                 std::list<secp256k1_frost_nonce_commitment> commit_list) override {
        std::cout << "COMPUTE BLOCCO " << msg_hash.to_hex() << std::endl;
        secp256k1_frost_signature_share signature_shares[4];

        std::cout << "---- STO IN compute riga 746 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        if (sigs_frost.size() == 3) {
            std::cout << "AGGREGOOOOO" << std::endl;
            secp256k1_context *sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            //provo a stampare chiavi pub partecipanti
            for (auto & i : sigs_frost) {
                std::cout << "i = " <<i.first << std::endl;
            }
            std::vector<const secp256k1_frost_signature_share*> signature_shares_vec;
            signature_shares_vec.reserve(sigs_frost.size());
            for (const auto& pair : sigs_frost) {
                signature_shares_vec.push_back(&pair.second);
            }
            const bytearray_t &msg = msg_hash.to_bytes();
            size_t num_commitments = commit_list.size();
            std::vector<secp256k1_frost_nonce_commitment> commitments_vec(commit_list.begin(), commit_list.end());

            /*
            int return_val = secp256k1_frost_aggregate(sign_verify_ctx, signature, (unsigned char *) &*msg.begin(),
                                                       keypair, public_keys, commitments_vec.data(),
                                                       *signature_shares_vec.data(), 3);
            assert(return_val == 1);
             */
        }

   }
    void compute() override {};

    bool verify(const ReplicaConfig &config) override;
    promise_t verify(const ReplicaConfig &config, VeriPool &vpool) override;

    const uint256_t &get_obj_hash() const override { return obj_hash; }

    QuorumCertFrost *clone() override {
        std::cout << "---- STO IN clone riga 754 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        return new QuorumCertFrost(*this);
    }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 794 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;

        s  << obj_hash << rids<<frost;
        std::cout << "obj_hash == " << obj_hash.to_hex() << std::endl;
        std::cout << "frost == " << frost << std::endl;
        std::cout << "rids.size() = " << rids.size() << std::endl;
        std::cout << "sigs_frost.size() = " << sigs_frost.size() << std::endl;
        std::cout << "sigs.size() = " << sigs.size() << std::endl;

        if (!frost) {
            for (size_t i = 0; i < rids.size(); i++)
                if (rids.get(i)) s << sigs.at(i);
        }
        else {
            // Serialize for frost case
            size_t num_elements = sigs_frost.size();
            s << num_elements;
            for (const auto &entry : sigs_frost) {
                s << entry.first << entry.second.index;
                for (unsigned char c : entry.second.response) {
                    s << c;
                }
            }
        }

    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 805 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;

        s >> obj_hash >> rids>>frost;
        std::cout << "obj_hash == " << obj_hash.to_hex() << std::endl;
        std::cout << "frost == " << frost << std::endl;

        if (!frost) {
            for (size_t i = 0; i < rids.size(); i++)
                if (rids.get(i)) s >> sigs[i];
        } else {
            // Unserialize for frost case
            ReplicaID rid;
            secp256k1_frost_signature_share share;
            size_t num_elements;
            s >> num_elements;
            for (size_t i = 0; i < num_elements; ++i) {
                s >> rid >> share.index;
                for (unsigned char & j : share.response) {
                    s >> j;
                }
                sigs_frost.emplace(rid, share);
            }
        }



    }

    const salticidae::Bits &getRids() const;

    void setRids(const salticidae::Bits &rids);

};

class QuorumCertSecp256k1: public QuorumCert {
    uint256_t obj_hash;
    salticidae::Bits rids;
    std::unordered_map<ReplicaID, SigSecp256k1> sigs;
    std::map<ReplicaID, secp256k1_frost_signature_share> sigs_frost;

    public:
    QuorumCertSecp256k1() = default;
    QuorumCertSecp256k1(const ReplicaConfig &config, const uint256_t &obj_hash);

    void add_part(ReplicaID rid, const PartCert &pc) override {
        std::cout << "---- STO IN add_part riga 475 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        if (pc.get_obj_hash() != obj_hash)
            throw std::invalid_argument("PartCert does match the block hash");
        sigs.insert(std::make_pair(
            rid, static_cast<const PartCertSecp256k1 &>(pc)));
        rids.set(rid);
    }

    salticidae::Bits getRids() override {}
    std::map<ReplicaID, secp256k1_frost_signature_share> get_sigs_frost() override {}

    void add_part(ReplicaID rid, const PartCertFrost &pc) override {
        std::cout << "---- STO IN add_part riga QuorumCertFrost 746 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

    }
    std::list<ReplicaID> get_index_voters() override {}
    void compute(const uint256_t blob, const secp256k1_frost_keypair *keypair,secp256k1_frost_pubkey *public_keys,
                 std::list<secp256k1_frost_nonce_commitment> commit_list) override {
        std::cout << "---- STO IN compute riga 486 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
    }

    void compute() override {};
    bool verify(const ReplicaConfig &config) override;
    promise_t verify(const ReplicaConfig &config, VeriPool &vpool) override;

    const uint256_t &get_obj_hash() const override { return obj_hash; }

    QuorumCertSecp256k1 *clone() override {
        std::cout << "---- STO IN clone riga 494 DENTRO crypto.h package:include->hotstuff---- " << std::endl;

        return new QuorumCertSecp256k1(*this);
    }

    void serialize(DataStream &s) const override {
        std::cout << "---- STO IN serialize riga 859 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;

        s  << obj_hash << rids;
        std::cout << "obj_hash == " << obj_hash.to_hex() << std::endl;

        for (size_t i = 0; i < rids.size(); i++)
            if (rids.get(i)) s << sigs.at(i);
    }

    void unserialize(DataStream &s) override {
        std::cout << "---- STO IN unserialize riga 870 DENTRO crypto.h package:include->hotstuff---- " << std::endl;
        std::cout << "s = " << s.get_hex() << std::endl;
        std::cout << "obj_hash == " << obj_hash.to_hex() << std::endl;
        s >> obj_hash >> rids;
        for (size_t i = 0; i < rids.size(); i++)
            if (rids.get(i)) s >> sigs[i];
    }
};

}

#endif
