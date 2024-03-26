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

#include <iostream>
#include "hotstuff/entity.h"
#include "hotstuff/crypto.h"
#include "secp256k1_frost.h"

#include "eckey_impl.h"
#include "secp256k1.h"
//#include "../secp256k1-frost/src/modules/frost/main_impl.h"

namespace hotstuff {

secp256k1_context_t secp256k1_default_sign_ctx = new Secp256k1Context(true);
secp256k1_context_t secp256k1_default_verify_ctx = new Secp256k1Context(false);

QuorumCertSecp256k1::QuorumCertSecp256k1(const ReplicaConfig &config, const uint256_t &obj_hash):
            QuorumCert(), obj_hash(obj_hash), rids(config.nreplicas){
    std::cout << "---- STO IN QuorumCertSecp256k1 riga 26 DENTRO crypto.cpp package:salticidae->include->src---- " << std::endl;

    rids.clear();
}


    QuorumCertFrost::QuorumCertFrost(const ReplicaConfig &config, const uint256_t &obj_hash, bool frost):
            QuorumCert(), obj_hash(obj_hash), rids(config.nreplicas), frost(frost){
        std::cout << "---- STO IN QuorumCertFrost riga 26 DENTRO crypto.cpp package:salticidae->include->src---- " << std::endl;

        rids.clear();
    }


bool QuorumCertSecp256k1::verify(const ReplicaConfig &config) {
    std::cout << "---- STO IN verify riga 35 DENTRO crypto.cpp package:salticidae->include->src---- " << std::endl;

    if (sigs.size() < config.nmajority) return false;
    for (size_t i = 0; i < rids.size(); i++)
        if (rids.get(i))
        {
            HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                                i, get_hex10(obj_hash).c_str());
            if (!sigs[i].verify(obj_hash,
                            static_cast<const PubKeySecp256k1 &>(config.get_pubkey(i)),
                            secp256k1_default_verify_ctx))
            return false;
        }
    return true;
}

promise_t QuorumCertSecp256k1::verify(const ReplicaConfig &config, VeriPool &vpool) {
    std::cout << "---- STO IN verify riga 52 DENTRO crypto.cpp package:salticidae->include->src---- " << std::endl;
    
    if (sigs.size() < config.nmajority)
        return promise_t([](promise_t &pm) { pm.resolve(false); });
    std::vector<promise_t> vpm;
    for (size_t i = 0; i < rids.size(); i++)
        if (rids.get(i))
        {
            HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                                i, get_hex10(obj_hash).c_str());
            vpm.push_back(vpool.verify(new Secp256k1VeriTask(obj_hash,
                            static_cast<const PubKeySecp256k1 &>(config.get_pubkey(i)),
                            sigs[i])));
        }
    return promise::all(vpm).then([](const promise::values_t &values) {
        for (const auto &v: values)
            if (!promise::any_cast<bool>(v)) return false;
        return true;
    });
}


    bool QuorumCertFrost::verify(const ReplicaConfig &config) {
        std::cout << "---- STO IN verify riga 35 DENTRO crypto.cpp package:salticidae->include->src---- " << std::endl;

        if (sigs.size() < config.nmajority) return false;
        for (size_t i = 0; i < rids.size(); i++)
            if (rids.get(i))
            {
                HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                                   i, get_hex10(obj_hash).c_str());
                if (!sigs[i].verify(obj_hash,
                                    static_cast<const PubKeySecp256k1 &>(config.get_pubkey(i)),
                                    secp256k1_default_verify_ctx))
                    return false;
            }
        return true;
    }

/*
    void QuorumCertFrost::compute(const uint256_t msg_hash, const secp256k1_frost_keypair *keypair,secp256k1_frost_pubkey *public_keys,
                 std::list<secp256k1_frost_nonce_commitment> commit_list)  {
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

        int return_val = secp256k1_frost_aggregate(sign_verify_ctx, signature, (unsigned char *) &*msg.begin(),
                                                   keypair, public_keys, commitments_vec.data(),
                                                   *signature_shares_vec.data(), 3);
        assert(return_val == 1);
        }



}*/

    promise_t QuorumCertFrost::verify(const ReplicaConfig &config, VeriPool &vpool) {
        std::cout << "---- STO IN verify riga 52 DENTRO crypto.cpp package:salticidae->include->src---- " << std::endl;

        if (sigs.size() < config.nmajority)
            return promise_t([](promise_t &pm) { pm.resolve(false); });
        std::vector<promise_t> vpm;
        for (size_t i = 0; i < rids.size(); i++)
            if (rids.get(i))
            {
                HOTSTUFF_LOG_DEBUG("checking cert(%d), obj_hash=%s",
                                   i, get_hex10(obj_hash).c_str());
                vpm.push_back(vpool.verify(new Secp256k1VeriTask(obj_hash,
                                                                 static_cast<const PubKeySecp256k1 &>(config.get_pubkey(i)),
                                                                 sigs[i])));
            }
        return promise::all(vpm).then([](const promise::values_t &values) {
            for (const auto &v: values)
                if (!promise::any_cast<bool>(v)) return false;
            return true;
        });
    }




}
