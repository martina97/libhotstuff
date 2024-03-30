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

#include <cassert>
#include <stack>
#include <iostream>
#include <ostream>

#include "hotstuff/util.h"
#include "hotstuff/consensus.h"
#include "secp256k1_frost.h"
#include <secp256k1_frost.h>
#include "secp256k1-frost/examples/examples_util.h"
#include <random>
#include <algorithm>
#define LOG_INFO HOTSTUFF_LOG_INFO
#define LOG_DEBUG HOTSTUFF_LOG_DEBUG
#define LOG_WARN HOTSTUFF_LOG_WARN
#define LOG_PROTO HOTSTUFF_LOG_PROTO
//#define EXAMPLE_MAX_PARTICIPANTS 4
namespace hotstuff {

/* The core logic of HotStuff, is fairly simple :). */
/*** begin HotStuff protocol logic ***/
HotStuffCore::HotStuffCore(ReplicaID id, privkey_bt &&priv_key):
        b0(new Block(true, 1)),
        b_lock(b0),
        b_exec(b0),
        vheight(0),
        priv_key(std::move(priv_key)),
        tails{b0},
        vote_disabled(false),
        id(id),
        storage(new EntityStorage()) {
    storage->add_blk(b0);
}

void HotStuffCore::sanity_check_delivered(const block_t &blk) {
    std::cout << "---- STO IN sanity_check_delivered riga 49 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    if (!blk->delivered)
        throw std::runtime_error("block not delivered");
}

block_t HotStuffCore::get_delivered_blk(const uint256_t &blk_hash) {
    std::cout << "---- STO IN get_delivered_blk riga 56 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    block_t blk = storage->find_blk(blk_hash);
    if (blk == nullptr || !blk->delivered)
        throw std::runtime_error("block not delivered");
    return blk;
}

bool HotStuffCore::on_deliver_blk(const block_t &blk) {
    std::cout << "---- STO IN on_deliver_blk riga 65 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    if (blk->delivered)
    {
        LOG_WARN("attempt to deliver a block twice");
        return false;
    }
    blk->parents.clear();
    for (const auto &hash: blk->parent_hashes)
        blk->parents.push_back(get_delivered_blk(hash));
    blk->height = blk->parents[0]->height + 1;

    if (blk->qc)
    {
        block_t _blk = storage->find_blk(blk->qc->get_obj_hash());
        if (_blk == nullptr)
            throw std::runtime_error("block referred by qc not fetched");
        blk->qc_ref = std::move(_blk);
    } // otherwise blk->qc_ref remains null

    for (auto pblk: blk->parents) tails.erase(pblk);
    tails.insert(blk);

    blk->delivered = true;
    LOG_DEBUG("deliver %s", std::string(*blk).c_str());
    return true;
}

void HotStuffCore::update_hqc(const block_t &_hqc, const quorum_cert_bt &qc) {
    std::cout << "---- STO IN update_hqc riga 94 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    if (_hqc->height > hqc.first->height)
    {
        hqc = std::make_pair(_hqc, qc->clone());
        on_hqc_update();
    }
}

void HotStuffCore::update(const block_t &nblk) {
    std::cout << "---- STO IN update riga 104 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;
    
    /* nblk = b*, blk2 = b'', blk1 = b', blk = b */
#ifndef HOTSTUFF_TWO_STEP
    /* three-step HotStuff */
    std::cout << "three-step HotStuff" << std::endl;

    const block_t &blk2 = nblk->qc_ref;
    if (blk2 == nullptr) return;
    /* decided blk could possible be incomplete due to pruning */
    if (blk2->decision) return;
    update_hqc(blk2, nblk->qc);

    const block_t &blk1 = blk2->qc_ref;
    if (blk1 == nullptr) return;
    if (blk1->decision) return;
    if (blk1->height > b_lock->height) b_lock = blk1;

    const block_t &blk = blk1->qc_ref;
    if (blk == nullptr) return;
    if (blk->decision) return;

    /* commit requires direct parent */
    if (blk2->parents[0] != blk1 || blk1->parents[0] != blk) return;
#else
    /* two-step HotStuff */

    const block_t &blk1 = nblk->qc_ref;
    if (blk1 == nullptr) return;
    if (blk1->decision) return;
    update_hqc(blk1, nblk->qc);
    if (blk1->height > b_lock->height) b_lock = blk1;

    const block_t &blk = blk1->qc_ref;
    if (blk == nullptr) return;
    if (blk->decision) return;

    /* commit requires direct parent */
    if (blk1->parents[0] != blk) return;
#endif
    /* otherwise commit */
    std::vector<block_t> commit_queue;
    block_t b;
    for (b = blk; b->height > b_exec->height; b = b->parents[0])
    { /* TODO: also commit the uncles/aunts */
        commit_queue.push_back(b);
    }
    if (b != b_exec)
        throw std::runtime_error("safety breached :( " +
                                std::string(*blk) + " " +
                                std::string(*b_exec));
    for (auto it = commit_queue.rbegin(); it != commit_queue.rend(); it++)
    {
        const block_t &blk = *it;
        blk->decision = 1;
        std::cout << "PRIMA DI DO_CONSENSUS" << std::endl;
        do_consensus(blk);
        std::cout << "DOPO DO_CONSENSUS" << std::endl;


        LOG_PROTO("commit %s", std::string(*blk).c_str());
        for (size_t i = 0; i < blk->cmds.size(); i++) {
            std::cout << "prima di do_decide" << std::endl;
            
            do_decide(Finality(id, 1, i, blk->height,
                               blk->cmds[i], blk->get_hash()));
        }
    }
    b_exec = blk;
}

    bool indexComparator(const secp256k1_frost_nonce_commitment& a, const secp256k1_frost_nonce_commitment& b) {
        return a.index < b.index;
    }

/**
Chiamata per inviare nuovi comandi da decidere (eseguire).
"parents" deve contenere almeno un blocco e il primo blocco è il genitore effettivo, mentre gli altri sono uncles/aunts.
 */
block_t HotStuffCore::on_propose(const std::vector<uint256_t> &cmds, const std::vector<block_t> &parents, bytearray_t &&extra) {
    std::cout << "---- STO IN on_propose riga 177 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;
    
    if (parents.empty())
        throw std::runtime_error("empty parents");
    for (const auto &_: parents) tails.erase(_);
    std::cout << "ALL INIZIO DI ON PROPOSE MAP SIZE = "  << commitment_map.size() << std::endl;



    if (!commitment_map.empty()) {
        // Get an iterator to the first element of the map
        auto it = commitment_map.begin();
        std::cout << "element list num = " << it->second.size() << std::endl;
        for (const auto& pair : commitment_map) {
            const std::string& key = pair.first;
            std::cout << "Key: " << key << "\tnum element = " << pair.second.size() << std::endl;
        }
    }




        
    std::cout << "parents[0]->get_hash().to_hex() = " << parents[0]->get_hash().to_hex() << std::endl;
    bool frost = true;


    if (commitment_map.empty() or commitment_map.begin()->second.size() < config.nmajority) {
        //if (commitment_map.empty() or commitment_map.size() < 3) {
        std::cout << "NIENTE FROST!!!!!!!! " << std::endl;
        frost = false;
    }

    /* create the new block */
    block_t bnew = storage->add_blk(
        new Block(parents, cmds, frost,
            hqc.second->clone(), std::move(extra),
            parents[0]->height + 1,
            hqc.first,
            nullptr
        ));

    std::cout << "parents[0]->get_hash().to_hex() = " << bnew->parents[0]->get_hash().to_hex() << std::endl;
   // bnew->frost = frost;
    const uint256_t bnew_hash = bnew->get_hash();

    on_deliver_blk(bnew);
    std::cout << "CHIAMO UPDATE DENTRO on_propose" << std::endl;

    update(bnew);
    std::cout << "dopo update" << std::endl;
    //bnew->qc_frost = QuorumCertFrost(config, bnew_hash);


    Proposal prop(frost,id, bnew, nullptr);
    bnew->self_qc = create_quorum_cert(bnew_hash, frost);
    //bnew->self_qc = create_quorum_cert(bnew_hash);
    std::cout << "PROVO A STAMPARE IL QC ---- " << bnew->self_qc->to_hex() << std::endl;


    if (frost) {
        //std::cout << "bnew->qc_frost.obj_hash.to_hex() "<< bnew->qc_frost.obj_hash.to_hex() << std::endl;
        std::cout << "FROST ABILITATO DENTRO ON PROPOSE !!!!" << std::endl;
        // Whenever you access commitment_map, lock the mutex first
        {
            /**ORA DEVO SCEGLIERE QUALI SARANNO I FIRMATARI !!! GENERO RANDOMICAMENTE config.nmajority INDICI
             * DA 0 A config.nreplicas */

            std::lock_guard<std::mutex> lock(map_mutex);
            auto first_element = commitment_map.begin();
            prop.commitment_list = new std::list<secp256k1_frost_nonce_commitment>();

            // Copy the commitments from the list in the map to the new list
            for (const auto& commitment : first_element->second) {
                prop.commitment_list->push_back(commitment);
            }
            std::string key = get_hex10(bnew_hash);
            prop.commitment_list->sort(indexComparator);
            commitment_map_aggregation.emplace_back(key, *prop.commitment_list);
            
            // Iterate over the list and print each element
            std::cout << "Printing commitment list:" << std::endl;
            std::cout << "Commitment list SIZE = "  << prop.commitment_list->size()<< std::endl;
            for (const auto &commitment : *prop.commitment_list) {
                std::cout << "Index: " << commitment.index << std::endl;
                std::cout << "Hiding: ";
                for (unsigned char i : commitment.hiding) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                }
                std::cout << std::endl;
                std::cout << "Binding: ";
                for (unsigned char i : commitment.binding) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                }
                std::cout << std::endl;
            }

            //std::copy(first_element.begin(), first_element.end(), bnew->list_commitment);
            commitment_map.erase(commitment_map.begin()); //tolgo il primo valore della mappa, in quanto l'ho usato!!!

        }
    }

    std::cout << "dopo prop" << std::endl;
    
    LOG_PROTO("propose %s", std::string(*bnew).c_str());
    if (bnew->height <= vheight)
        throw std::runtime_error("new block should be higher than vheight");
    /* self-receive the proposal (no need to send it through the network) */
    on_receive_proposal(prop);
    on_propose_(prop);
    /* broadcast to other replicas */
    do_broadcast_proposal(prop);
    return bnew;
}

/** Funzione chiamata alla consegna di un messaggio di proposta (PROPOSAL).
 * Il blocco menzionato nel messaggio dovrebbe essere già consegnato.*/
void HotStuffCore::on_receive_proposal(const Proposal &prop) {
    std::cout << "---- STO IN on_receive_proposal riga 215 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;
    std::mutex nonce_list_mutex;
    LOG_PROTO("got %s", std::string(prop).c_str());
    bool self_prop = prop.proposer == get_id();
    block_t bnew = prop.blk;
    std::cout << "bnew.frost === " << bnew->frost << std::endl;
    
    if (!self_prop)
    {
        sanity_check_delivered(bnew);
        std::cout << "CHIAMO UPDATE DENTRO on_receive_proposal" << std::endl;

        update(bnew);
    }
    bool opinion = false;
    if (bnew->height > vheight)
    {
        if (bnew->qc_ref && bnew->qc_ref->height > b_lock->height)
        {
            opinion = true; // liveness condition
            vheight = bnew->height;
        }
        else
        {   // safety condition (extend the locked branch)
            block_t b;
            for (b = bnew;
                b->height > b_lock->height;
                b = b->parents[0]);
            if (b == b_lock) /* on the same branch */
            {
                opinion = true;
                vheight = bnew->height;
            }
        }
    }
    LOG_PROTO("now state: %s", std::string(*this).c_str());
    if (!self_prop && bnew->qc_ref)
        on_qc_finish(bnew->qc_ref);
    on_receive_proposal_(prop);
    if (opinion && !vote_disabled) {
        std::cout << "----- DO VOTE ------ " << std::endl;
        std::cout << "PRIMA DI CREATE PART CERT" << std::endl;

        //part_cert_bt boh = create_part_cert(*priv_key, bnew->get_hash());
        //std::cout << "DOPO CREATE PART CERT" << std::endl;

        /** PRIMA DI CREARE IL VOTO GENERO COPPIA NONCE-COMMITMENT PER IL BLOCCO SUCCESSIVO !
         *  PER VOTARE USO I COMMITMENT CREATI NELLA FASE PRECEDENTE DI VOTO, SE IL FLAG "frost" = true
         * */
        std::cout <<"nonce_list.size() = "<< nonce_list.size()<< std::endl;


        /**
         * IDEA: SE nonce.list è vuota, vuol dire che è la prima volta che voto, quindi che aggiungo un blocco,
         * per cui posso dire che se:
         * size ==0 --> firma senza FROST (quindi senza nonce-commitment)
         * size != 0 --> prendi il primo elemento nella lista di nonce, vedi se nonce non è usato, e lo inserisci nel msg voto
         */

        if (!bnew->frost) {

            if (!fill_random(binding_seed, sizeof(binding_seed))) {
                throw HotStuffError("Failed to generate binding_seed\n");

            }
            if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
                throw HotStuffError("Failed to generate hiding_seed\n");

            }
            secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(sign_verify_ctx, key_pair, binding_seed, hiding_seed);
            {
                //std::lock_guard<std::mutex> lock(nonce_list_mutex);

                nonce_list.push_back(nonce);
                std::cout << "NONCE LIST SIZE = " << nonce_list.size() << std::endl;


                const Vote vote = Vote(bnew->frost,true,id,bnew->get_hash(), create_part_cert(*priv_key, bnew->get_hash()), &nonce->commitments,this);
                std::cout << "dopo aver creato il vote!!" << std::endl;
                std::cout <<"msg.vote.commitment->index = " <<vote.commitment->index << std::endl;
                std::cout <<"msg.vote.commitment->hiding = " <<std::endl;
                std::cout << "0x";
                for (unsigned char i : vote.commitment->hiding) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                }
                std::cout << std::dec << std::endl; // Reset to decimal format
                std::cout <<"msg.vote.commitment->binding = " <<std::endl;
                std::cout << "0x";
                for (unsigned char i : vote.commitment->binding) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                }
                std::cout << std::dec << std::endl; // Reset to decimal format

                std::cout << "BLOCCOOOOO = === = = =" << bnew->get_hash().to_hex() << std::endl;

                do_vote(prop.proposer, vote);
                //nonce_list.erase(nonce_list.begin()); non l'ho usato per firmare --> non devo cancellarlo
            }

        } else{
            std::cout << "CREO VOTO FROST !!!! " << std::endl;
            
            /** FROST **/
            // creo certificato con firme frost !
            /*
            std::cout << "signature_share->response"<< std::endl;
            for (unsigned char i : signature_share->response) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
            }
            std::cout << std::endl;
             */
            if (!fill_random(binding_seed, sizeof(binding_seed))) {
                throw HotStuffError("Failed to generate binding_seed\n");

            }
            if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
                throw HotStuffError("Failed to generate hiding_seed\n");

            }
            /** CREO NUOVA COPPIA NONCE-COMM DA USARE PER IL PROX BLOCCO */
            secp256k1_frost_nonce *nonce = secp256k1_frost_nonce_create(sign_verify_ctx, key_pair, binding_seed, hiding_seed);
            
                nonce_list.push_back(nonce);
                std::cout << "0x";
                for (unsigned char i : nonce->commitments.hiding) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                }
                std::cout << std::dec << std::endl; // Reset to decimal format
                std::cout << "prop.commitment_list->size() = " << prop.commitment_list->size() << std::endl;

                /** METTO COMMITMENT DENTRO VOTE MSG */
                std::vector<secp256k1_frost_nonce_commitment> signing_commitments;
                for (const auto& commitment : *prop.commitment_list) {
                    signing_commitments.push_back(commitment);
                }
                
                /** stampo hiding del mio commitment, e mi stampo anche la lista di hiding nel signing commitments */
                for (unsigned char i : nonce_list[0]->commitments.hiding) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                }
                std::cout << std::endl;

                std::cout << "STAMPO COMMITMENT NELLA LISTA" << std::endl;
                
                for (const auto& commitment : signing_commitments) {
                    for (unsigned char i : commitment.hiding) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                    }
                    std::cout << std::endl;

                }
                std::cout << "----" << std::endl;
                std::cout << "bloccoooooo ======  " << bnew->get_hash().to_hex() << std::endl;

                bool found = false;
                for (auto & signing_commitment : signing_commitments) {
                    if (memcmp(nonce_list[0]->commitments.hiding, signing_commitment.hiding, 64) == 0) {
                        found = true;
                        break;
                    }
                }
                std::cout << "PROVO A STAMPARE KEY PAIR MAX PARTECIPANTS " << std::endl;
                std::cout << "key_pair->public_keys.max_participants = " << key_pair->public_keys.max_participants << std::endl;
                
                
                if (!found) {
                    // se il mio commitment non c'è nella lista --> NON VOTO!! CREO CERTIFICATO NORMALE !
                    HOTSTUFF_LOG_WARN("commitment not in list");
                    //auto *frost_cert = new hotstuff::PartCertFrost(bnew->get_hash(), true);
                    auto *frost_cert = new hotstuff::PartCertFrost(bnew->get_hash(),
                                                                   EXAMPLE_MIN_PARTICIPANTS, key_pair, nonce_list[0],signing_commitments.data());
                    if (frost_cert->signature_share == nullptr) {
                        std::cout << "CERTIFICATO NULLO ! "  << std::endl;
                    }
                    const Vote vote = Vote(true,false, id, bnew->get_hash(), frost_cert, &nonce->commitments,this);
                    nonce_list.erase(nonce_list.begin());
                    do_vote(prop.proposer, vote);

                } else {
                    auto *frost_cert = new hotstuff::PartCertFrost(bnew->get_hash(),
                                                                   EXAMPLE_MIN_PARTICIPANTS, key_pair, nonce_list[0],signing_commitments.data());
                    std::cout << "signature_share->response"<< std::endl;
                    for (unsigned char i : frost_cert->signature_share->response) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
                    }
                    std::cout << std::endl;
                    const Vote vote = Vote(true,true,id, bnew->get_hash(), frost_cert, &nonce->commitments,this);
                    std::cout << "cert frost blk hash = " << frost_cert->obj_hash.to_hex() << std::endl;
                    //std::copy(std::begin(bnew->list_commitment), std::end(bnew->list_commitment), std::begin(signing_commitments));
                    std::cout << "nonce_list_size = " << nonce_list.size() << std::endl;
                    /** CREO PART CERT CON I COMMITMENT PRESI NEL MSG PROPOSE ! --> if blk.frost = true !!! */

                    nonce_list.erase(nonce_list.begin());
                    do_vote(prop.proposer, vote);

                }





                //const Vote vote = Vote(bnew->frost,id, bnew->get_hash(), create_part_cert(*priv_key, bnew->get_hash()), &nonce->commitments,this);

                //Vote vote = Vote(id, bnew->get_hash(), frost_cert ,&nonce->commitments, this);
                //const Vote vote = Vote(id, bnew->get_hash() ,&nonce->commitments, this);  todo scommenta


                

                //vote.frost=true;


        }
    }
}


void HotStuffCore::on_receive_vote(const Vote &vote) {
    std::cout << "---- STO IN on_receive_vote riga 272 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;


    /** CI ENTRA SOLO IL LEADER --> POSSO PRENDERMI I COMMITMENT */
    LOG_PROTO("got %s", std::string(vote).c_str());
    LOG_PROTO("now state: %s", std::string(*this).c_str());

    std::cout << "HO RICEVUTO VOTO, CONTROLLO I COMMITMENT PASSATI!" << std::endl;
    std::cout << "vote.frost = " << vote.frost << std::endl;

    /*
    if (vote.commitment->index != 0) {
        vote.commitment->index = vote.commitment->index / 256;
    }*/
    std::cout << "BLOCCOOOOO = === = = =" << vote.blk_hash.to_hex() << std::endl;
    std::cout << "vote.commitment->index = " << vote.commitment->index << std::endl;
    std::cout <<"msg.vote.commitment->hiding = " <<std::endl;
    std::cout << "0x";
    for (unsigned char i : vote.commitment->hiding) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
    }
    std::cout << std::dec << std::endl; // Reset to decimal format

    std::cout <<"msg.vote.commitment->binding = " <<std::endl;
    std::cout << "0x";
    for (unsigned char i : vote.commitment->binding) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
    }
    std::cout << std::dec << std::endl; // Reset to decimal format

    block_t blk = get_delivered_blk(vote.blk_hash);
    if (vote.frost == 0) {
        assert(vote.cert);
    } else if (vote.frost == 1 and vote.is_valid == 1) {
        std::cout << "vote.frost == 1 and vote.is_valid == 1" << std::endl;
        assert(vote.cert_frost);
        assert(vote.cert_frost->signature_share);
    }



    size_t qsize = blk->voted.size();
    std::cout << "config.nmajority = " << config.nmajority << std::endl;
    std::cout << "qsize = " << blk->voted.size() << std::endl;

    if (qsize >= config.nmajority) {
        std::cout << "qsize >= config.nmajority" << std::endl;
        return;
    }
    if (vote.is_valid != 0) {   // lo inserisco solo se voto è valido!
        if (!blk->voted.insert(vote.voter).second)
        {
            LOG_WARN("duplicate vote for %s from %d", get_hex10(vote.blk_hash).c_str(), vote.voter);
            return;
        }
    }

    std::cout << "qsize = " << blk->voted.size() << std::endl;
    auto &qc = blk->self_qc;
    if (qc == nullptr)
    {
        LOG_WARN("vote for block not proposed by itself");
        qc = create_quorum_cert(blk->get_hash(), vote.frost);
    }
    std::cout << "PRIMA DI ADD_PART!!!" << std::endl;

    //qc->add_part(vote.voter, *vote.cert);
    /**  ORA DEVO METTERE IL COMMITMENT NELLA MAPPA !!!! */

    std::string key = get_hex10(vote.blk_hash);
    std::mutex commitment_map_mutex;
    // se gia ne ho messi 3, quindi ho gia 3 voti, non li metto

    {
        // Create a scoped lock to lock the mutex
        std::lock_guard<std::mutex> lock(commitment_map_mutex);
        // Check if the key already exists in the vector
        auto it = std::find_if(commitment_map.begin(), commitment_map.end(),
                               [&key](const auto& pair) { return pair.first == key; });

        if (it != commitment_map.end()) {
            // If the key exists, append the commitment to the associated list
            it->second.push_back(*vote.commitment);
        } else {
            // If the key doesn't exist, create a new pair and insert it into the vector
            std::list<secp256k1_frost_nonce_commitment> newCommitmentList;
            newCommitmentList.push_back(*vote.commitment);
            commitment_map.emplace_back(key, std::move(newCommitmentList));
        }
    }
    if (vote.frost == 0) {

        std::cout << "ADD PART CLASSICO" << std::endl;
        std::cout << " vote.cert->to_hex() = " << vote.cert->to_hex() << std::endl;
        qc->add_part(vote.voter, *vote.cert);
    }  else if (vote.frost == 1 and vote.is_valid == 1) {
        //ADD PART FROST TODO
        std::cout << "PROVO A STAMPARE CERT FROST ! " << std::endl;
        std::cout << "vote.cert_frost = " << vote.cert_frost->to_hex() << std::endl;
        
        std::cout << " vote.cert_frost->obj_hash.to_hex() = " << vote.cert_frost->obj_hash.to_hex() << std::endl;
        std::cout << "vote.cert_frost->signature_share->response = " << std::endl;
        for (unsigned char i : vote.cert_frost->signature_share->response) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        }
        std::cout << std::endl;
        qc->add_part(vote.voter, *vote.cert_frost);
    }


    //if (qsize + 1 == config.nmajority)
    if (blk->voted.size() == config.nmajority)
    {
        std::cout << "qsize + 1 == config.nmajority" << std::endl;
        std::cout << "----------------------- CHIAMO COMPUTEEEEEEE -------------------------" << std::endl;
        
        if (blk->frost == 1) {
            secp256k1_frost_pubkey pk[EXAMPLE_MAX_PARTICIPANTS];
            for (const ReplicaID& id : blk->voted) {
                std::cout << "id = " << id << std::endl;

                pk[id] = public_keys[id];
                secp256k1_frost_pubkey &boh = public_keys[id];
                std::cout << "STAMPO CHIAVE PUB" << std::endl;
                for (size_t i = 0; i < 33; i++) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(boh.public_key[i]);
                }
                std::cout << std::dec << std::endl;

                std::cout << "STAMPO CHIAVE PUB GRUPPO" << std::endl;
                for (size_t i = 0; i < 33; i++) {
                    std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(boh.group_public_key[i]);
                }
                std::cout << std::dec << std::endl;

            }
            auto it = std::find_if(commitment_map_aggregation.begin(), commitment_map_aggregation.end(),
                                   [&](const auto& pair) { return pair.first == key; });
            // If key is found, print commitments
            if (it != commitment_map_aggregation.end()) {
                std::cout << "Commitments for key: " << key << std::endl;
                for (const auto& commitment : it->second) {
                    std::cout << "Index: " << commitment.index << std::endl;
                    std::cout << "Hiding: ";
                    for (size_t i = 0; i < sizeof(commitment.hiding); ++i) {
                        std::cout << std::hex << std::setw(2) << std::setfill('0')
                                  << static_cast<int>(commitment.hiding[i]);
                    }
                    std::cout << std::dec << std::endl;
                }
            } else {
                std::cout << "Key not found: " << key << std::endl;
            }
            //qc->compute(blk->get_hash(), key_pair, pk, it->second);
            const salticidae::Bits &rids = qc->getRids();
            auto sigs_frost = qc->get_sigs_frost();
            std::cout << "stampo i sigs frost fuori compute" << std::endl;
            if (sigs_frost.size() == EXAMPLE_MIN_PARTICIPANTS) {
                for (auto &i: sigs_frost) {
                    std::cout << "i = " << i.first << std::endl;
                    std::cout << "i.index = " << i.second.index << std::endl;
                }
                std::cout << "AGGREGOOOOO" << std::endl;
                unsigned char signature[64];
                secp256k1_context *sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
                //provo a stampare chiavi pub partecipanti
                for (auto & i : sigs_frost) {
                    std::cout << "i = " <<i.first << std::endl;
                }
                std::vector<secp256k1_frost_signature_share> signature_shares_vec;
                signature_shares_vec.reserve(sigs_frost.size());
                for (const auto& pair : sigs_frost) {
                    std::cout << "indici sig frost = " <<pair.first << std::endl;
                    //secp256k1_frost_signature_share *sig = &pair.second;
                   // sig->index = pair.first;

                    signature_shares_vec.push_back(pair.second);
                }
                const bytearray_t &msg = blk->get_hash().to_bytes();
                size_t num_commitments = it->second.size();
                std::vector<secp256k1_frost_nonce_commitment> commitments_vec(it->second.begin(), it->second.end());

                for (int i = 0; i < EXAMPLE_MAX_PARTICIPANTS; ++i) {
                    public_keys[i].index = i;
                    std::cout << "Index: " << public_keys[i].index << std::endl;
                }


                auto *qc2 = new QuorumCertFrost(blk->get_hash(), rids, sigs_frost);
                std::cout << "provaa " << qc2->obj_hash.to_hex() << std::endl;

                for (const auto& pair : signature_shares_vec) {
                    std::cout << "pair->index = " << pair.index << std::endl;

                }
                qc2->aggrego(sign_verify_ctx, signature, (unsigned char *) &*msg.begin(),
                            key_pair, pk, commitments_vec.data(),
                            signature_shares_vec.data(), EXAMPLE_MIN_PARTICIPANTS);
                /*
                int return_val = secp256k1_frost_aggregate(sign_verify_ctx, signature, (unsigned char *) &*msg.begin(),
                                                           key_pair, pk, commitments_vec.data(),
                                                           *signature_shares_vec.data(), 3);
                assert(return_val == 1);
                 */
                }


            }

            update_hqc(blk, qc);
            on_qc_finish(blk);
        }
    }
    /*** end HotStuff protocol logic ***/
void HotStuffCore::on_init(uint32_t nfaulty) {
    std::cout << "---- STO IN on_init riga 301 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;
    config.nmajority = config.nreplicas - nfaulty;
    std::cout << "config.nmajority  == " << config.nmajority << std::endl;
    std::cout << "b0->get_hash().to_hex() == " << b0->get_hash().to_hex() << std::endl;


    // b0->qc è quorum_cert_bt , ossia QuorumCert
    b0->qc = create_quorum_cert(b0->get_hash(), false);    //Create a quorum certificate that proves 2f+1 votes for a block.
    std::cout << "b0->qc.get()->to_hex() = " << b0->qc.get()->to_hex() << std::endl;
    std::cout << "b0->height = " << b0->height << std::endl;

    std::cout << "Values of b0->cmds:" << std::endl;
    for (const auto& value : b0->cmds) {
        std::cout << value.to_hex()<< " ";
           // Assuming uint256_t supports ostream insertion
    }
    std::cout << std::endl;


    b0->qc->compute();  //todo: vedere issue su THRESHOLD SIGNATURES
    b0->self_qc = b0->qc->clone();
    b0->qc_ref = b0;
    hqc = std::make_pair(b0, b0->qc->clone());
    std::cout << "FINE on_init" << std::endl;
    
}

void HotStuffCore::prune(uint32_t staleness) {
    std::cout << "---- STO IN prune riga 329 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    block_t start;
    /* skip the blocks */
    for (start = b_exec; staleness; staleness--, start = start->parents[0])
        if (!start->parents.size()) return;
    std::stack<block_t> s;
    start->qc_ref = nullptr;
    s.push(start);
    while (!s.empty())
    {
        auto &blk = s.top();
        if (blk->parents.empty())
        {
            storage->try_release_blk(blk);
            s.pop();
            continue;
        }
        blk->qc_ref = nullptr;
        s.push(blk->parents.back());
        blk->parents.pop_back();
    }
}

void HotStuffCore::add_replica(ReplicaID rid, const PeerId &peer_id,
                                pubkey_bt &&pub_key) {
    std::cout << "---- STO IN add_replica riga 354 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;
    std::cout << " pub_key->to_hex() = " <<  pub_key->to_hex() << std::endl;


    config.add_replica(rid,ReplicaInfo(rid, peer_id, std::move(pub_key)));
    //aggiungo l'id della replica nell'insieme "voted", che memorizza gli id di tutte le
    //repliche che hanno votato per il blocco b0
   // b0->voted.insert(rid);  /** b0 = genesis block, ossia blocco iniziale blockchain */
}

void HotStuffCore::add_replica_frost(ReplicaID rid, const PeerId &peer_id, hotstuff::PubKeyFrost &pub_key) {
    std::cout << "---- STO IN add_replica_frost riga 354 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;
    //print_hex2(pub_key.public_key, sizeof(pub_key.public_key));

    /*
    printf("0x");
    for (i = 0; i < sizeof(pub_key.public_key); i++) {
        printf("%02x", pub_key.public_key[i]);
    }
    printf("\n");
     */


    std::cout << "PROVO A STAMPARE PUB KEY" << std::endl;
    auto serializedKeys = pub_key.serializePubKeys();

    std::cout << "0x";
    for (size_t i = 0; i < 33; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(serializedKeys.first[i]);
    }
    std::cout << std::dec << std::endl; // Reset to decimal format

    /*
    std::cout << pub_key.get()->to_hex() << std::endl;
    std::cout << "DOPO AVER STAMPATO PUB KEY" << std::endl;


     */
    config.add_replica(rid,ReplicaInfoFrost(rid, peer_id, pub_key));

    b0->voted.insert(rid);

    secp256k1_frost_pubkey pub_key_to_insert;
    std::copy(serializedKeys.first.begin(), serializedKeys.first.end(), pub_key_to_insert.public_key);
    std::copy(serializedKeys.second.begin(), serializedKeys.second.end(), pub_key_to_insert.group_public_key);
    pub_key_to_insert.index = rid;
    std::cout << "config.nreplicas = " << config.nreplicas << std::endl;

    pub_key_to_insert.max_participants = EXAMPLE_MAX_PARTICIPANTS;
    // Insert pub_key_to_insert into public_keys array
    public_keys[rid] = pub_key_to_insert;




}
    void HotStuffCore::add_keypair_frost(ReplicaID rid, hotstuff::PubKeyFrost &pub_key) {
    std::cout << "----- STO IN add_keypair_frost ------" << std::endl;
        key_pair = new secp256k1_frost_keypair;
        std::cout << "priv k = " << priv_key->to_hex().data() << std::endl;
        std::cout << "priv k = " << priv_key->to_hex().c_str() << std::endl;
        std::cout << sizeof(priv_key->to_bytes()) << std::endl;
        

        memcpy(key_pair->secret, (unsigned char *)&*priv_key->to_bytes().begin(), 32);
        //key_pair->secret = (unsigned char *)&*priv_key->to_bytes().begin();
        std::cout << "Secret: ";
        std::cout << priv_key->to_hex() << std::endl;
        
        std::cout << std::endl;
        auto pubkey = pub_key.serializePubKeys();
        std::copy(pubkey.first.begin(), pubkey.first.end(), key_pair->public_keys.public_key);
        std::copy(pubkey.second.begin(), pubkey.second.end(), key_pair->public_keys.group_public_key);
        key_pair->public_keys.index = rid;
        std::cout << "config.nreplicas = " << config.nreplicas << std::endl;
        
        key_pair->public_keys.max_participants = EXAMPLE_MAX_PARTICIPANTS;


        std::cout << "DOPO ADD KEY PAIR PROVO A STAMPARE" << std::endl;

        for (std::size_t i = 0; i < 33; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_pair->public_keys.public_key[i]);
        }
        std::cout << "" << std::endl;
        for (std::size_t i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(key_pair->secret[i]);
        }
        std::cout << "" << std::endl;

        
        std::cout << "" << std::endl;
        sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

        /*
        signature_share = new secp256k1_frost_signature_share;
        signature_share->index = rid;
        memcpy(signature_share->response,(unsigned char *)&*priv_key->to_bytes().begin(), 32);
        std::cout << "HO INIZIALIZZATO LA MIA SIGNATURE SHARE !!!!" << std::endl;
         */
        

    }



promise_t HotStuffCore::async_qc_finish(const block_t &blk) {
    std::cout << "---- STO IN async_qc_finish riga 356 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    if (blk->voted.size() >= config.nmajority)
        return promise_t([](promise_t &pm) {
            pm.resolve();
        });
    auto it = qc_waiting.find(blk);
    if (it == qc_waiting.end())
        it = qc_waiting.insert(std::make_pair(blk, promise_t())).first;
    return it->second;
}

void HotStuffCore::on_qc_finish(const block_t &blk) {
    std::cout << "---- STO IN on_qc_finish riga 378 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    auto it = qc_waiting.find(blk);
    if (it != qc_waiting.end())
    {
        it->second.resolve();
        qc_waiting.erase(it);
    }
}

promise_t HotStuffCore::async_wait_proposal() {
    std::cout << "---- STO IN async_wait_proposal riga 389 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    return propose_waiting.then([](const Proposal &prop) {
        return prop;
    });
}

promise_t HotStuffCore::async_wait_receive_proposal() {
    std::cout << "---- STO IN async_wait_receive_proposal riga 397 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    return receive_proposal_waiting.then([](const Proposal &prop) {
        return prop;
    });
}

promise_t HotStuffCore::async_hqc_update() {
    std::cout << "---- STO IN async_hqc_update riga 405 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    return hqc_update_waiting.then([this]() {
        return hqc.first;
    });
}

void HotStuffCore::on_propose_(const Proposal &prop) {
    std::cout << "---- STO IN on_propose riga 413 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    auto t = std::move(propose_waiting);
    propose_waiting = promise_t();
    t.resolve(prop);
}

void HotStuffCore::on_receive_proposal_(const Proposal &prop) {
    std::cout << "---- STO IN on_receive_proposal_ riga 421 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    auto t = std::move(receive_proposal_waiting);
    receive_proposal_waiting = promise_t();
    t.resolve(prop);
}

void HotStuffCore::on_hqc_update() {
    std::cout << "---- STO IN on_hqc_update riga 429 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    auto t = std::move(hqc_update_waiting);
    hqc_update_waiting = promise_t();
    t.resolve();
}

HotStuffCore::operator std::string () const {
    std::cout << "---- STO IN std::string riga 437 DENTRO consensus.cpp package:salticidae->include->src---- " << std::endl;

    DataStream s;
    s << "<hotstuff "
      << "hqc=" << get_hex10(hqc.first->get_hash()) << " "
      << "hqc.height=" << std::to_string(hqc.first->height) << " "
      << "b_lock=" << get_hex10(b_lock->get_hash()) << " "
      << "b_exec=" << get_hex10(b_exec->get_hash()) << " "
      << "vheight=" << std::to_string(vheight) << " "
      << "tails=" << std::to_string(tails.size()) << ">";
    return s;
}

}
