/**
 * Copyright (c) woodser
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Parts of this file are originally copyright (c) 2014-2019, The Monero Project
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 * All rights reserved.
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list of
 *    conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list
 *    of conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without specific
 *    prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers
 */

#include <boost/optional/optional.hpp>
#include "monero_utils.h"
#include "rpc/core_rpc_server_commands_defs.h"
#include "storages/portable_storage_template_helper.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "seraphis_main/enote_scanning_context.h"
#include "seraphis_main/enote_scanning.h"
#include "seraphis_main/enote_scanning_utils.h"
#include "seraphis_main/enote_finding_context.h"
#include "common/threadpool.h"
#include "seraphis_core/tx_extra.h"
#include "seraphis_core/legacy_core_utils.h"
#include "seraphis_mocks/enote_store_mock_v1.h"
#include "seraphis_mocks/enote_store_updater_mocks.h"
#include "seraphis_mocks/enote_finding_context_mocks.h"
#include "mnemonics/electrum-words.h"
#include "mnemonics/english.h"
#include "string_tools.h"
#include "byte_stream.h"
#include "net/http.h"
#include "storages/http_abstract_invoke.h"
#include "ringct/rctTypes.h"
#include "cryptonote_basic/cryptonote_basic.h"

using namespace cryptonote;
using namespace monero_utils;

// --------------------------- VALIDATION UTILS -------------------------------

monero_integrated_address monero_utils::get_integrated_address(monero_network_type network_type, const std::string& standard_address, const std::string& payment_id) {

  // parse and validate address
  cryptonote::address_parse_info address_info;
  if (!get_account_address_from_str(address_info, static_cast<cryptonote::network_type>(network_type), standard_address)) throw std::runtime_error("Invalid address");
  if (address_info.has_payment_id) throw std::runtime_error("The given address already has a payment id");

  // randomly generate payment id if not given, else validate
  crypto::hash8 payment_id_h8;
  if (payment_id.empty()) {
    payment_id_h8 = crypto::rand<crypto::hash8>();
  } else {
    cryptonote::blobdata payment_id_data;
    if (!epee::string_tools::parse_hexstr_to_binbuff(payment_id, payment_id_data) || sizeof(crypto::hash8) != payment_id_data.size()) throw std::runtime_error("Invalid payment id");
    payment_id_h8 = *reinterpret_cast<const crypto::hash8*>(payment_id_data.data());
  }

  // build integrated address
  monero_integrated_address integrated_address;
  integrated_address.m_integrated_address = cryptonote::get_account_integrated_address_as_str(static_cast<cryptonote::network_type>(network_type), address_info.address, payment_id_h8);
  integrated_address.m_standard_address = standard_address;
  integrated_address.m_payment_id = epee::string_tools::pod_to_hex(payment_id_h8);
  return integrated_address;
}

bool monero_utils::is_valid_address(const std::string& address, monero_network_type network_type) {
  try {
    validate_address(address, network_type);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_private_view_key(const std::string& private_view_key) {
  try {
    validate_private_view_key(private_view_key);
    return true;
  } catch (...) {
    return false;
  }
}

bool monero_utils::is_valid_private_spend_key(const std::string& private_spend_key) {
  try {
    validate_private_spend_key(private_spend_key);
    return true;
  } catch (...) {
    return false;
  }
}

void monero_utils::validate_address(const std::string& address, monero_network_type network_type) {
  cryptonote::address_parse_info info;
  if (!get_account_address_from_str(info, static_cast<cryptonote::network_type>(network_type), address)) throw std::runtime_error("Invalid address");
}

void monero_utils::validate_private_view_key(const std::string& private_view_key) {
  if (private_view_key.length() != 64) throw std::runtime_error("private view key expected to be 64 hex characters");
  cryptonote::blobdata private_view_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(private_view_key, private_view_key_data) || private_view_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("private view key expected to be 64 hex characters");
  }
}

void monero_utils::validate_private_spend_key(const std::string& private_spend_key) {
  if (private_spend_key.length() != 64) throw std::runtime_error("private spend key expected to be 64 hex characters");
  cryptonote::blobdata private_spend_key_data;
  if (!epee::string_tools::parse_hexstr_to_binbuff(private_spend_key, private_spend_key_data) || private_spend_key_data.size() != sizeof(crypto::secret_key)) {
    throw std::runtime_error("private spend key expected to be 64 hex characters");
  }
}

// -------------------------- BINARY SERIALIZATION ----------------------------

void monero_utils::json_to_binary(const std::string &json, std::string &bin) {
  epee::serialization::portable_storage ps;
  ps.load_from_json(json);
  epee::byte_stream bs;
  ps.store_to_binary(bs);
  bin = std::string((char*) bs.data(), bs.size());
}

void monero_utils::binary_to_json(const std::string &bin, std::string &json) {
  epee::serialization::portable_storage ps;
  ps.load_from_binary(bin);
  ps.dump_as_json(json);
}

void monero_utils::binary_blocks_to_json(const std::string &bin, std::string &json) {

  // load binary rpc response to struct
  cryptonote::COMMAND_RPC_GET_BLOCKS_BY_HEIGHT::response resp_struct;
  epee::serialization::load_t_from_binary(resp_struct, bin);

  // build property tree from deserialized blocks and transactions
  boost::property_tree::ptree root;
  boost::property_tree::ptree blocksNode; // array of block strings
  boost::property_tree::ptree txsNodes;   // array of txs per block (array of array)
  for (int blockIdx = 0; blockIdx < resp_struct.blocks.size(); blockIdx++) {

    // parse and validate block
    cryptonote::block block;
    if (cryptonote::parse_and_validate_block_from_blob(resp_struct.blocks[blockIdx].block, block)) {

      // add block node to blocks node
      boost::property_tree::ptree blockNode;
      blockNode.put("", cryptonote::obj_to_json_str(block));  // TODO: no pretty print
      blocksNode.push_back(std::make_pair("", blockNode));
    } else {
      throw std::runtime_error("failed to parse block blob at index " + std::to_string(blockIdx));
    }

    // parse and validate txs
    boost::property_tree::ptree txs_node;
    for (int txIdx = 0; txIdx < resp_struct.blocks[blockIdx].txs.size(); txIdx++) {
      cryptonote::transaction tx;
      if (cryptonote::parse_and_validate_tx_from_blob(resp_struct.blocks[blockIdx].txs[txIdx].blob, tx)) {

        // add tx node to txs node
        boost::property_tree::ptree txNode;
        //MTRACE("PRUNED:\n" << monero_utils::get_pruned_tx_json(tx));
        txNode.put("", monero_utils::get_pruned_tx_json(tx)); // TODO: no pretty print
        txs_node.push_back(std::make_pair("", txNode));
      } else {
        throw std::runtime_error("failed to parse tx blob at index " + std::to_string(txIdx));
      }
    }
    txsNodes.push_back(std::make_pair("", txs_node)); // array of array of transactions, one array per block
  }
  root.add_child("blocks", blocksNode);
  root.add_child("txs", txsNodes);
  root.put("status", resp_struct.status);
  root.put("untrusted", resp_struct.untrusted); // TODO: loss of ints and bools

  // convert root to string // TODO: common utility with serial_bridge
  std::stringstream ss;
  boost::property_tree::write_json(ss, root, false/*pretty*/);
  json = ss.str();
}

// ------------------------------- RAPIDJSON ----------------------------------

std::string monero_utils::serialize(const rapidjson::Document& doc) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  doc.Accept(writer);
  return buffer.GetString();
}

void monero_utils::add_json_member(std::string key, std::string val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root, rapidjson::Value& field) {
  rapidjson::Value field_key(key.c_str(), key.size(), allocator);
  field.SetString(val.c_str(), val.size(), allocator);
  root.AddMember(field_key, field, allocator);
}

void monero_utils::add_json_member(std::string key, bool val, rapidjson::Document::AllocatorType& allocator, rapidjson::Value& root) {
  rapidjson::Value field_key(key.c_str(), key.size(), allocator);
  if (val) {
    rapidjson::Value field_val(rapidjson::kTrueType);
    root.AddMember(field_key, field_val, allocator);
  } else {
    rapidjson::Value field_val(rapidjson::kFalseType);
    root.AddMember(field_key, field_val, allocator);
  }
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<std::string>& strs) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_str(rapidjson::kStringType);
  for (const std::string& str : strs) {
    value_str.SetString(str.c_str(), str.size(), allocator);
    value_arr.PushBack(value_str, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint8_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetInt(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

// TODO: remove these redundant implementations for different sizes?
rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint32_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetUint64(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

rapidjson::Value monero_utils::to_rapidjson_val(rapidjson::Document::AllocatorType& allocator, const std::vector<uint64_t>& nums) {
  rapidjson::Value value_arr(rapidjson::kArrayType);
  rapidjson::Value value_num(rapidjson::kNumberType);
  for (const auto& num : nums) {
    value_num.SetUint64(num);
    value_arr.PushBack(value_num, allocator);
  }
  return value_arr;
}

// ------------------------ PROPERTY TREES ---------------------------

std::string monero_utils::serialize(const boost::property_tree::ptree& node) {
  std::stringstream ss;
  boost::property_tree::write_json(ss, node, false);
  std::string str = ss.str();
  return str.substr(0, str.size() - 1); // strip newline
}

void monero_utils::deserialize(const std::string& json, boost::property_tree::ptree& root) {
  std::istringstream iss = json.empty() ? std::istringstream() : std::istringstream(json);
  try {
    boost::property_tree::read_json(iss, root);
  } catch (std::exception const& e) {
    throw std::runtime_error("Invalid JSON");
  }
}

// ----------------------------------------------------------------------------

bool monero_utils::is_valid_language(const std::string& language) {
  std::vector<std::string> languages;
  crypto::ElectrumWords::get_language_list(languages, false);
  std::vector<std::string>::iterator it = std::find(languages.begin(), languages.end(), language);
  if (it == languages.end()) {
    crypto::ElectrumWords::get_language_list(languages, true);
    it = std::find(languages.begin(), languages.end(), language);
  }
  if (it == languages.end()) return false;
  return true;
}

// TODO: this is unused
std::shared_ptr<monero_block> monero_utils::cn_block_to_block(const cryptonote::block& cn_block) {
  cryptonote::block temp = cn_block;
  std::cout << cryptonote::obj_to_json_str(temp) << std::endl;
  std::shared_ptr<monero_block> block = std::make_shared<monero_block>();
  block->m_major_version = cn_block.major_version;
  block->m_minor_version = cn_block.minor_version;
  block->m_timestamp = cn_block.timestamp;
  block->m_prev_hash = epee::string_tools::pod_to_hex(cn_block.prev_id);
  block->m_nonce = cn_block.nonce;
  block->m_miner_tx = monero_utils::cn_tx_to_tx(cn_block.miner_tx);
  for (const crypto::hash& tx_hash : cn_block.tx_hashes) {
    block->m_tx_hashes.push_back(epee::string_tools::pod_to_hex(tx_hash));
  }
  return block;
}

std::shared_ptr<monero_tx> monero_utils::cn_tx_to_tx(const cryptonote::transaction& cn_tx, bool init_as_tx_wallet) {
  std::shared_ptr<monero_tx> tx = init_as_tx_wallet ? std::make_shared<monero_tx_wallet>() : std::make_shared<monero_tx>();
  tx->m_version = cn_tx.version;
  tx->m_unlock_height = cn_tx.unlock_time;
  tx->m_hash = epee::string_tools::pod_to_hex(cn_tx.hash);
  tx->m_extra = cn_tx.extra;

  // init inputs
  for (const txin_v& cnVin : cn_tx.vin) {
    if (cnVin.which() != 0 && cnVin.which() != 3) throw std::runtime_error("Unsupported variant type");
    if (tx->m_is_miner_tx == boost::none) tx->m_is_miner_tx = cnVin.which() == 0;
    if (cnVin.which() != 3) continue; // only process txin_to_key of variant  TODO: support other types, like 0 "gen" which is miner tx?
    std::shared_ptr<monero_output> input = init_as_tx_wallet ? std::make_shared<monero_output_wallet>() : std::make_shared<monero_output>();
    input->m_tx = tx;
    tx->m_inputs.push_back(input);
    const txin_to_key& txin = boost::get<txin_to_key>(cnVin);
    input->m_amount = txin.amount;
    input->m_ring_output_indices = txin.key_offsets;
    crypto::key_image cnKeyImage = txin.k_image;
    input->m_key_image = std::make_shared<monero_key_image>();
    input->m_key_image.get()->m_hex = epee::string_tools::pod_to_hex(cnKeyImage);
  }

  // init outputs
  for (const tx_out& cnVout : cn_tx.vout) {
    std::shared_ptr<monero_output> output = init_as_tx_wallet ? std::make_shared<monero_output_wallet>() : std::make_shared<monero_output>();
    output->m_tx = tx;
    tx->m_outputs.push_back(output);
    output->m_amount = cnVout.amount;
    const crypto::public_key& cnStealthPublicKey = boost::get<txout_to_tagged_key>(cnVout.target).key;
    output->m_stealth_public_key = epee::string_tools::pod_to_hex(cnStealthPublicKey);
  }

  return tx;

  // TODO: finish this, cryptonote::transaction has:
//  std::vector<std::vector<crypto::signature> > m_signatures;
//  rct::rctSig m_rct_signatures;
//  mutable size_t blob_size;
}

void add_default_subaddresses(
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map)
{
    const uint32_t SUBADDR_MAJOR_DEFAULT_LOOKAHEAD = 50;
    const uint32_t SUBADDR_MINOR_DEFAULT_LOOKAHEAD = 200;

    for (uint32_t i = 0; i < SUBADDR_MAJOR_DEFAULT_LOOKAHEAD; ++i)
    {
        for (uint32_t j = 0; j < SUBADDR_MINOR_DEFAULT_LOOKAHEAD; ++j)
        {
            const cryptonote::subaddress_index subaddr_index{i, j};

            rct::key legacy_subaddress_spendkey;

            sp::make_legacy_subaddress_spendkey(
                legacy_base_spend_pubkey,
                legacy_view_privkey,
                subaddr_index,
                hw::get_device("default"),
                legacy_subaddress_spendkey
            );

            legacy_subaddress_map[legacy_subaddress_spendkey] = subaddr_index;
        }
    }
};

typedef std::vector<std::pair<cryptonote::block, std::vector<std::pair<cryptonote::transaction, boost::optional<uint64_t>>>>> parsed_blocks_t;

void parse_get_blocks(const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res, parsed_blocks_t &blocks)
{
  // parse blocks and txs
  blocks.clear();
  blocks.reserve(res.blocks.size());
  for (int blockIdx = 0; blockIdx < res.blocks.size(); blockIdx++)
  {
    cryptonote::block block;
    if (!cryptonote::parse_and_validate_block_from_blob(res.blocks[blockIdx].block, block))
    {
      throw std::runtime_error("failed to parse block blob at index " + std::to_string(blockIdx));
    }

    std::vector<std::pair<cryptonote::transaction, boost::optional<uint64_t>>> txs;
    txs.reserve(res.blocks[blockIdx].txs.size());
    for (int txIdx = 0; txIdx < res.blocks[blockIdx].txs.size(); txIdx++)
    {
      cryptonote::transaction tx;
      if (!cryptonote::parse_and_validate_tx_base_from_blob(res.blocks[blockIdx].txs[txIdx].blob, tx))
      {
        throw std::runtime_error("failed to parse tx blob at index " + std::to_string(txIdx));
      }

      // total_output_count_before_tx == global output index of first output in tx
      boost::optional<uint64_t> total_output_count_before_tx = !res.output_indices[blockIdx].indices[txIdx].indices.empty()
        ? boost::optional<uint64_t>(res.output_indices[blockIdx].indices[txIdx].indices[0])
        : boost::none;

      txs.emplace_back(std::make_pair(std::move(tx), std::move(total_output_count_before_tx)));
    }

    blocks.emplace_back(std::make_pair(std::move(block), std::move(txs)));
  }
}

void parse_get_blocks(tools::threadpool &tpool, tools::threadpool::waiter &waiter, const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res, parsed_blocks_t &blocks)
{
    // parse blocks and txs
    blocks.resize(res.blocks.size());
    for (int blockIdx = 0; blockIdx < res.blocks.size(); blockIdx++)
    {
        tpool.submit(&waiter, [&, blockIdx]{
            if (!cryptonote::parse_and_validate_block_from_blob(res.blocks[blockIdx].block, blocks[blockIdx].first))
            {
                throw std::runtime_error("failed to parse block blob at index " + std::to_string(blockIdx));
            }
        }, true);
      }
    if (!waiter.wait())
        throw std::runtime_error("Failed waiting to parse blocks");

    // parse txs
    for (int blockIdx = 0; blockIdx < res.blocks.size(); blockIdx++)
    {
        blocks[blockIdx].second.resize(res.blocks[blockIdx].txs.size());
        for (int txIdx = 0; txIdx < res.blocks[blockIdx].txs.size(); txIdx++)
        {
            tpool.submit(&waiter, [&, blockIdx, txIdx]{
                if (!cryptonote::parse_and_validate_tx_base_from_blob(res.blocks[blockIdx].txs[txIdx].blob, blocks[blockIdx].second[txIdx].first))
                {
                    throw std::runtime_error("failed to parse tx blob at index " + std::to_string(txIdx));
                }

                // total_output_count_before_tx == global output index of first output in tx
                blocks[blockIdx].second[txIdx].second = !res.output_indices[blockIdx].indices[txIdx].indices.empty()
                    ? boost::optional<uint64_t>(res.output_indices[blockIdx].indices[txIdx].indices[0])
                    : boost::none;
            }, true);
        }
    }
    if (!waiter.wait())
      throw std::runtime_error("Failed waiting to parse txs");
}

bool is_encoded_amount_v1(const cryptonote::transaction &tx)
{
    return tx.rct_signatures.type == rct::RCTTypeFull || tx.rct_signatures.type == rct::RCTTypeSimple || tx.rct_signatures.type == rct::RCTTypeBulletproof;
}

bool is_encoded_amount_v2(const cryptonote::transaction &tx)
{
    return tx.rct_signatures.type == rct::RCTTypeBulletproof2 || tx.rct_signatures.type == rct::RCTTypeCLSAG || tx.rct_signatures.type == rct::RCTTypeBulletproofPlus;
}

bool is_legacy_enote_v1(const cryptonote::transaction &tx, const cryptonote::tx_out &out)
{
    return tx.version == 1 || (cryptonote::is_coinbase(tx) && out.target.type() == typeid(cryptonote::txout_to_key)); 
}

bool is_legacy_enote_v2(const cryptonote::transaction &tx, const cryptonote::tx_out &out)
{
    return !cryptonote::is_coinbase(tx) && tx.version == 2 && out.target.type() == typeid(cryptonote::txout_to_key) &&
        is_encoded_amount_v1(tx);
}

bool is_legacy_enote_v3(const cryptonote::transaction &tx, const cryptonote::tx_out &out)
{
    return !cryptonote::is_coinbase(tx) && tx.version == 2 && out.target.type() == typeid(cryptonote::txout_to_key) &&
        is_encoded_amount_v2(tx);
}

bool is_legacy_enote_v4(const cryptonote::transaction &tx, const cryptonote::tx_out &out)
{
    return cryptonote::is_coinbase(tx) && tx.version == 2 && out.target.type() == typeid(cryptonote::txout_to_tagged_key); 
}

bool is_legacy_enote_v5(const cryptonote::transaction &tx, const cryptonote::tx_out &out)
{
    return !cryptonote::is_coinbase(tx) && tx.version == 2 && out.target.type() == typeid(cryptonote::txout_to_tagged_key) &&
        is_encoded_amount_v2(tx);
}

bool try_out_to_legacy_enote_v1(const cryptonote::transaction &tx, const size_t output_index, sp::LegacyEnoteVariant &enote)
{
    if (output_index >= tx.vout.size())
        return false;
    if (!is_legacy_enote_v1(tx, tx.vout[output_index]))
        return false;

    sp::LegacyEnoteV1 enote_v1;

    /// Ko
    crypto::public_key out_pub_key;
    cryptonote::get_output_public_key(tx.vout[output_index], out_pub_key);
    enote_v1.m_onetime_address = rct::pk2rct(out_pub_key);
    /// a
    enote_v1.m_amount = tx.vout[output_index].amount;

    enote = std::move(enote_v1);
    return true;
}

bool try_out_to_legacy_enote_v2(const cryptonote::transaction &tx, const size_t output_index, sp::LegacyEnoteVariant &enote)
{
    if (output_index >= tx.vout.size())
        return false;
     if (!is_legacy_enote_v2(tx, tx.vout[output_index]))
        return false;

    sp::LegacyEnoteV2 enote_v2;

    /// Ko
    crypto::public_key out_pub_key;
    cryptonote::get_output_public_key(tx.vout[output_index], out_pub_key);
    enote_v2.m_onetime_address = rct::pk2rct(out_pub_key);
    /// C
    enote_v2.m_amount_commitment = tx.rct_signatures.outPk[output_index].mask;
    /// enc(x)
    enote_v2.m_encoded_amount_blinding_factor = tx.rct_signatures.ecdhInfo[output_index].mask;
    /// enc(a)
    enote_v2.m_encoded_amount = tx.rct_signatures.ecdhInfo[output_index].amount;

    enote = std::move(enote_v2);
    return true;
}

bool try_out_to_legacy_enote_v3(const cryptonote::transaction &tx, const size_t output_index, sp::LegacyEnoteVariant &enote)
{
    if (output_index >= tx.vout.size())
        return false;
    if (!is_legacy_enote_v3(tx, tx.vout[output_index]))
        return false;

    sp::LegacyEnoteV3 enote_v3;

    /// Ko
    crypto::public_key out_pub_key;
    cryptonote::get_output_public_key(tx.vout[output_index], out_pub_key);
    enote_v3.m_onetime_address = rct::pk2rct(out_pub_key);
    /// C
    enote_v3.m_amount_commitment = tx.rct_signatures.outPk[output_index].mask;
    /// enc(a)
    static_assert(sizeof(enote_v3.m_encoded_amount) <= sizeof(tx.rct_signatures.ecdhInfo[output_index].amount.bytes));
    memcpy(&enote_v3.m_encoded_amount, &tx.rct_signatures.ecdhInfo[output_index].amount.bytes, sizeof(enote_v3.m_encoded_amount));

    enote = std::move(enote_v3);
    return true;
}

bool try_out_to_legacy_enote_v4(const cryptonote::transaction &tx, const size_t output_index, sp::LegacyEnoteVariant &enote)
{
    if (output_index >= tx.vout.size())
        return false;
    if (!is_legacy_enote_v4(tx, tx.vout[output_index]))
        return false;

    sp::LegacyEnoteV4 enote_v4;

    /// Ko
    crypto::public_key out_pub_key;
    cryptonote::get_output_public_key(tx.vout[output_index], out_pub_key);
    enote_v4.m_onetime_address = rct::pk2rct(out_pub_key);
    /// a
    enote_v4.m_amount = tx.vout[output_index].amount;
    /// view_tag
    enote_v4.m_view_tag = *cryptonote::get_output_view_tag(tx.vout[output_index]);

    enote = std::move(enote_v4);
    return true;
}

bool try_out_to_legacy_enote_v5(const cryptonote::transaction &tx, const size_t output_index, sp::LegacyEnoteVariant &enote)
{
    if (output_index >= tx.vout.size())
        return false;
    if (!is_legacy_enote_v5(tx, tx.vout[output_index]))
        return false;

    sp::LegacyEnoteV5 enote_v5;

    /// Ko
    crypto::public_key out_pub_key;
    cryptonote::get_output_public_key(tx.vout[output_index], out_pub_key);
    enote_v5.m_onetime_address = rct::pk2rct(out_pub_key);
    /// C
    enote_v5.m_amount_commitment = tx.rct_signatures.outPk[output_index].mask;
    /// enc(a)
    static_assert(sizeof(enote_v5.m_encoded_amount) <= sizeof(tx.rct_signatures.ecdhInfo[output_index].amount.bytes));
    memcpy(&enote_v5.m_encoded_amount, &tx.rct_signatures.ecdhInfo[output_index].amount.bytes, sizeof(enote_v5.m_encoded_amount));
    /// view_tag
    enote_v5.m_view_tag = *cryptonote::get_output_view_tag(tx.vout[output_index]);

    enote = std::move(enote_v5);
    return true;
}

void outs_to_enotes(const cryptonote::transaction &tx, std::vector<sp::LegacyEnoteVariant> &enotes)
{
    enotes.clear();
    enotes.reserve(tx.vout.size());

    for (size_t i = 0; i < tx.vout.size(); ++i)
    {
        enotes.emplace_back();
        if (!try_out_to_legacy_enote_v1(tx, i, enotes.back())
            && !try_out_to_legacy_enote_v2(tx, i, enotes.back())
            && !try_out_to_legacy_enote_v3(tx, i, enotes.back())
            && !try_out_to_legacy_enote_v4(tx, i, enotes.back())
            && !try_out_to_legacy_enote_v5(tx, i, enotes.back())
        )
        {
            throw std::runtime_error("Unknown output type");
        }
    }
}

struct scan_enote_helper_t
{
    rct::key tx_hash;
    uint64_t height;
    uint64_t timestamp;
    boost::optional<uint64_t> total_output_count_before_tx;
    uint64_t unlock_time;
    sp::TxExtra tx_extra;
    std::vector<sp::LegacyEnoteVariant> enotes;
    std::vector<crypto::key_image> legacy_key_images;
};

void prepare_tx_for_enote_processing(
    const uint64_t height,
    const uint64_t timestamp,
    const crypto::hash &tx_hash,
    const cryptonote::transaction &tx,
    const boost::optional<uint64_t> total_output_count_before_tx,
    scan_enote_helper_t &seh)
{
    seh = scan_enote_helper_t{};

    seh.height = height;
    seh.timestamp = timestamp;
    seh.tx_hash = rct::hash2rct(tx_hash);
    seh.total_output_count_before_tx = total_output_count_before_tx;
    seh.unlock_time = tx.unlock_time;

    seh.tx_extra = sp::TxExtra(
        (const unsigned char *) tx.extra.data(),
        (const unsigned char *) tx.extra.data() + tx.extra.size()
    );

    outs_to_enotes(tx, seh.enotes);

    seh.legacy_key_images.reserve(tx.vin.size());
    for (const auto &in: tx.vin)
    {
        if (in.type() != typeid(cryptonote::txin_to_key))
            continue;
        const auto &txin = boost::get<cryptonote::txin_to_key>(in);
        seh.legacy_key_images.emplace_back(txin.k_image);
    }
}

void set_records_and_key_images(
    const rct::key &legacy_base_spend_pubkey,
    const crypto::secret_key &legacy_view_privkey,
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
    const std::vector<scan_enote_helper_t> &scan_enote_helper,
    sp::EnoteScanningChunkLedgerV1 &chunk_out)
{
    for (const auto &seh : scan_enote_helper)
    {
        // always add an entry for a tx in the basic records map (since we save key images for every tx)
        if (chunk_out.m_basic_records_per_tx.find(seh.tx_hash) == chunk_out.m_basic_records_per_tx.end())
        {
            chunk_out.m_basic_records_per_tx[seh.tx_hash] = std::list<sp::ContextualBasicRecordVariant>{};
        }

        // find owned enotes from tx
        if (seh.total_output_count_before_tx)
        {
            sp::try_find_legacy_enotes_in_tx(
                legacy_base_spend_pubkey,
                legacy_subaddress_map,
                legacy_view_privkey,
                seh.height,
                seh.timestamp,
                seh.tx_hash,
                *(seh.total_output_count_before_tx),
                seh.unlock_time,
                seh.tx_extra,
                seh.enotes,
                sp::SpEnoteOriginStatus::ONCHAIN,
                hw::get_device("default"),
                chunk_out.m_basic_records_per_tx
            );
        }

        // get ALL key images from the tx
        sp::collect_key_images_from_tx(
            seh.height,
            seh.timestamp,
            seh.tx_hash,
            seh.legacy_key_images,
            std::vector<crypto::key_image>(),
            sp::SpEnoteSpentStatus::SPENT_ONCHAIN,
            chunk_out.m_contextual_key_images
        );
    }
}

void prepare_chunk_out(
    const parsed_blocks_t &blocks,
    std::vector<scan_enote_helper_t> &seh_v,
    sp::EnoteScanningChunkLedgerV1 &chunk_out)
{
    chunk_out.m_basic_records_per_tx.clear();
    chunk_out.m_contextual_key_images.clear();
    chunk_out.m_block_ids.clear();

    chunk_out.m_block_ids.reserve(blocks.size());
    for (size_t blk_idx = 0; blk_idx < blocks.size(); ++blk_idx)
    {
        const auto &block_pair = blocks[blk_idx];
        const cryptonote::block &block = block_pair.first;
        uint64_t height = cryptonote::get_block_height(block);

        if (blk_idx == 0)
        {
            chunk_out.m_start_height = height;
            chunk_out.m_prefix_block_id = rct::hash2rct(block.prev_id);
        }

        if (blk_idx == blocks.size() - 1)
        {
            chunk_out.m_end_height = height + 1;
        }

        chunk_out.m_block_ids.emplace_back(rct::hash2rct(cryptonote::get_block_hash(block)));

        for (size_t txIdx = 0; txIdx < block_pair.second.size(); ++txIdx)
        {
            const cryptonote::transaction &tx = block_pair.second[txIdx].first;
            boost::optional<uint64_t> total_output_count_before_tx = block_pair.second[txIdx].second;
            seh_v.emplace_back();
            prepare_tx_for_enote_processing(height, block.timestamp, block.tx_hashes[txIdx], tx, total_output_count_before_tx, seh_v.back());
        }
    }
}

spends_and_receives_t monero_utils::identify_receives(const std::string &bin, const std::string &legacy_base_spend_pubkey_str, const std::string &legacy_view_privkey_str)
{
  spends_and_receives_t result;

  // load binary rpc response to struct
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response resp_struct;
  epee::serialization::load_t_from_binary(resp_struct, bin);

  parsed_blocks_t blocks;
  parse_get_blocks(resp_struct, blocks);

  // load keys
  rct::key legacy_base_spend_pubkey;
  crypto::secret_key legacy_view_privkey;
  epee::string_tools::hex_to_pod(legacy_base_spend_pubkey_str, legacy_base_spend_pubkey);
  epee::string_tools::hex_to_pod(legacy_view_privkey_str, legacy_view_privkey);

  std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
  add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

  // get a chunk of records that are owned by the user (scan the blocks with the view key)
  std::vector<scan_enote_helper_t> scan_enote_helper{};
  sp::EnoteScanningChunkLedgerV1 new_onchain_chunk{};
  prepare_chunk_out(blocks, scan_enote_helper, new_onchain_chunk);
  set_records_and_key_images(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map, scan_enote_helper, new_onchain_chunk);

  // process the chunk of records owned by the user (decrypt amounts)
  std::unordered_map<rct::key, sp::LegacyContextualIntermediateEnoteRecordV1> found_enote_records;
  std::unordered_map<crypto::key_image, sp::SpEnoteSpentContextV1> found_spent_key_images;
  sp::process_chunk_intermediate_legacy(
    legacy_base_spend_pubkey,
    legacy_view_privkey,
    [&](const crypto::key_image &key_image) -> bool
    {
      // no need to check key images, only care about receives
      return false;
    },
    new_onchain_chunk.m_basic_records_per_tx,
    new_onchain_chunk.m_contextual_key_images,
    hw::get_device("default"),
    found_enote_records,
    found_spent_key_images
  );

  // pack the response
  for (const auto &enote_record : found_enote_records)
  {
    result.push_back({
      false, // spend?
      epee::string_tools::pod_to_hex(enote_record.second.m_origin_context.m_transaction_id), // tx id
      epee::string_tools::pod_to_hex(sp::onetime_address_ref(enote_record.second.m_record.m_enote)), // output pub key
      enote_record.second.m_origin_context.m_block_height, // block height
      enote_record.second.m_record.m_amount // amount
    });
  }

  return result;
}

spends_and_receives_t monero_utils::identify_spends_and_receives(const std::string &bin, const std::string &legacy_spend_privkey_str, const std::string &legacy_view_privkey_str)
{
  spends_and_receives_t result;

  // load binary rpc response to struct
  cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response resp_struct;
  epee::serialization::load_t_from_binary(resp_struct, bin);
  parsed_blocks_t blocks;
  parse_get_blocks(resp_struct, blocks);

  // load keys
  /// spend key
  crypto::secret_key legacy_spend_privkey;
  crypto::public_key legacy_base_spend_pubkey_t;
  rct::key legacy_base_spend_pubkey;
  epee::string_tools::hex_to_pod(legacy_spend_privkey_str, legacy_spend_privkey);
  crypto::secret_key_to_public_key(legacy_spend_privkey, legacy_base_spend_pubkey_t);
  legacy_base_spend_pubkey = rct::pk2rct(legacy_base_spend_pubkey_t);
  /// view key
  crypto::secret_key legacy_view_privkey;
  epee::string_tools::hex_to_pod(legacy_view_privkey_str, legacy_view_privkey);

  std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
  add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

  // get a chunk of records that are owned by the user (scan the blocks with the view key)
  std::vector<scan_enote_helper_t> scan_enote_helper{};
  sp::EnoteScanningChunkLedgerV1 new_onchain_chunk{};
  set_records_and_key_images(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map, scan_enote_helper, new_onchain_chunk);

  // process the chunk of records owned by the user (decrypt amounts, generate key images, and determine spends)
  std::unordered_map<rct::key, sp::LegacyContextualEnoteRecordV1> found_enote_records;
  std::unordered_map<crypto::key_image, sp::SpEnoteSpentContextV1> found_spent_key_images;
  sp::process_chunk_full_legacy(
    legacy_base_spend_pubkey,
    legacy_spend_privkey,
    legacy_view_privkey,
    [&](const crypto::key_image &key_image) -> bool
    {
      // TODO: check if key image is known from prior received enotes
      return false;
    },
    new_onchain_chunk.m_basic_records_per_tx,
    new_onchain_chunk.m_contextual_key_images,
    hw::get_device("default"),
    found_enote_records,
    found_spent_key_images
  );

  // pack the response
  for (const auto &enote_record : found_enote_records)
  {
    result.push_back({
      false, // spend?
      epee::string_tools::pod_to_hex(enote_record.second.m_origin_context.m_transaction_id), // tx id
      epee::string_tools::pod_to_hex(sp::onetime_address_ref(enote_record.second.m_record.m_enote)), // output pub key
      enote_record.second.m_origin_context.m_block_height, // block height
      enote_record.second.m_record.m_amount, // amount
    });

    if (enote_record.second.m_spent_context.m_spent_status == sp::SpEnoteSpentStatus::SPENT_ONCHAIN)
    {
      result.push_back({
        true, // spend?
        epee::string_tools::pod_to_hex(enote_record.second.m_spent_context.m_transaction_id), // tx id
        epee::string_tools::pod_to_hex(sp::onetime_address_ref(enote_record.second.m_record.m_enote)), // output pub key
        enote_record.second.m_spent_context.m_block_height, // block height
        enote_record.second.m_record.m_amount, // amount
      });
    }
  }

  return result;
}

////
// EnoteFindingContextLedgerLegacy
// - finds owned enotes from legacy view scanning
///
class EnoteFindingContextLedgerLegacy final : public sp::EnoteFindingContextLedger
{
public:
//constructors
    EnoteFindingContextLedgerLegacy(
        const rct::key &legacy_base_spend_pubkey,
        const std::unordered_map<rct::key, cryptonote::subaddress_index> &legacy_subaddress_map,
        const crypto::secret_key &legacy_view_privkey) :
            m_legacy_base_spend_pubkey{legacy_base_spend_pubkey},
            m_legacy_subaddress_map{legacy_subaddress_map},
            m_legacy_view_privkey{legacy_view_privkey}
    {
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteFindingContextLedgerLegacy& operator=(EnoteFindingContextLedgerLegacy&&) = delete;

//member functions
    /// get an onchain chunk (or empty chunk representing top of current chain)
    void get_onchain_chunk(const std::uint64_t chunk_start_height,
        const std::uint64_t chunk_max_size,
        sp::EnoteScanningChunkLedgerV1 &chunk_out) const override {}
    /// try to get an unconfirmed chunk (no-op for legacy scanning)
    void get_unconfirmed_chunk(sp::EnoteScanningChunkNonLedgerV1 &chunk_out) const override {}
    /// scans enotes in a tx for basic records
    void find_basic_records(const scan_enote_helper_t &scan_enote_helper,
        std::unordered_map<rct::key, std::list<sp::ContextualBasicRecordVariant>> &basic_records) const;

//member variables
private:
    const rct::key &m_legacy_base_spend_pubkey;
    const std::unordered_map<rct::key, cryptonote::subaddress_index> &m_legacy_subaddress_map;
    const crypto::secret_key &m_legacy_view_privkey;
};

void EnoteFindingContextLedgerLegacy::find_basic_records(
    const scan_enote_helper_t &seh,
    std::unordered_map<rct::key, std::list<sp::ContextualBasicRecordVariant>> &basic_records) const
{
    if (seh.total_output_count_before_tx)
    {
        // find owned enotes from tx
        sp::try_find_legacy_enotes_in_tx(
            m_legacy_base_spend_pubkey,
            m_legacy_subaddress_map,
            m_legacy_view_privkey,
            seh.height,
            seh.timestamp,
            seh.tx_hash,
            *(seh.total_output_count_before_tx),
            seh.unlock_time,
            seh.tx_extra,
            seh.enotes,
            sp::SpEnoteOriginStatus::ONCHAIN,
            hw::get_device("default"),
            basic_records
        );
    }
}

typedef std::pair<parsed_blocks_t, uint64_t/*height*/> onchain_chunk_t;

void request_onchain_chunk(
    const std::uint64_t chunk_start_height,
    const std::uint64_t chunk_max_size,
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> &http_client,
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &res)
{
    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::request req;

    req.prune = true;
    req.start_height = chunk_start_height;
    req.no_miner_tx = false;
    bool r = epee::net_utils::invoke_http_bin("/getblocks.bin", req, res, *http_client, std::chrono::seconds(10));
    if (!r)
        throw std::runtime_error("Failed /getblocks.bin");
}

void set_final_chunk_out(const uint64_t chain_height, const uint64_t scan_height, const rct::key prefix_block_id, sp::EnoteScanningChunkLedgerV1 &chunk_out)
{
    if (chain_height != scan_height)
        throw std::runtime_error("Expected to have scanned up to tip");
    chunk_out.m_start_height = chain_height;
    chunk_out.m_end_height = chain_height;
    chunk_out.m_prefix_block_id = prefix_block_id;
}

void scan_legacy_chunk(
    tools::threadpool &tpool,
    tools::threadpool::waiter &waiter,
    const cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response &chunk_to_scan,
    const EnoteFindingContextLedgerLegacy &enote_finding_context,
    sp::EnoteScanningChunkLedgerV1 &chunk_out)
{
    // parse the chunk
    parsed_blocks_t blocks;
    parse_get_blocks(tpool, waiter, chunk_to_scan, blocks);

    // prepare chunk for scanning
    std::vector<scan_enote_helper_t> scan_enote_helper{};
    prepare_chunk_out(blocks, scan_enote_helper, chunk_out);

    // scan each tx
    std::vector<std::unordered_map<rct::key, std::list<sp::ContextualBasicRecordVariant>>> basic_records_per_tx_v;
    basic_records_per_tx_v.reserve(scan_enote_helper.size());
    for (const auto &seh : scan_enote_helper)
    {
        chunk_out.m_basic_records_per_tx[seh.tx_hash] = std::list<sp::ContextualBasicRecordVariant>{};

        if (seh.total_output_count_before_tx)
        {
            basic_records_per_tx_v.emplace_back();
            tpool.submit(&waiter, [&]{
                // writing to containers isn't thread safe; writing to a single
                // container from multiple threads is undefined behavior. Referencing
                // a fresh single-use container here is a hack for thread safety.
                enote_finding_context.find_basic_records(seh, basic_records_per_tx_v.back());
            }, true);
        }

        sp::collect_key_images_from_tx(
            seh.height,
            seh.timestamp,
            seh.tx_hash,
            seh.legacy_key_images,
            std::vector<crypto::key_image>(),
            sp::SpEnoteSpentStatus::SPENT_ONCHAIN,
            chunk_out.m_contextual_key_images
        );
    }
    if (!waiter.wait())
        throw std::runtime_error("Failed waiting for onchain chunk request");

    for (const auto &basic_records_per_tx : basic_records_per_tx_v)
    {
        for (const auto &brpt : basic_records_per_tx)
        {
            chunk_out.m_basic_records_per_tx[brpt.first] = std::move(brpt.second);
        }
    }
}

////
// EnoteScanningContextLedgerMultithreaded
// - acquires enote scanning chunks from a ledger context
// - meant to be used in a multithreaded context
///
class EnoteScanningContextLedgerMultithreaded final : public sp::EnoteScanningContextLedger
{
public:
//constructor
    EnoteScanningContextLedgerMultithreaded(const EnoteFindingContextLedgerLegacy &enote_finding_context):
        m_enote_finding_context{enote_finding_context},
        m_network_waiter{m_tpool},
        m_local_scanner_waiter(m_tpool)
    {
    }

//overloaded operators
    /// disable copy/move (this is a scoped manager [reference wrapper])
    EnoteScanningContextLedgerMultithreaded& operator=(EnoteScanningContextLedgerMultithreaded&&) = delete;

//member functions
    /// start scanning from a specified block height
    void begin_scanning_from_height(const std::uint64_t initial_start_height, const std::uint64_t max_chunk_size) override
    {
        m_next_start_height = initial_start_height;
        m_max_chunk_size = max_chunk_size;
    }
    /// get the next available onchain chunk
    /// - starting past the end of the last chunk acquired since starting to scan
    void get_onchain_chunk(sp::EnoteScanningChunkLedgerV1 &chunk_out) override
    {
        MINFO("Scanning " << m_next_start_height);

        chunk_out.m_basic_records_per_tx.clear();
        chunk_out.m_contextual_key_images.clear();
        chunk_out.m_block_ids.clear();

        if (m_finished_scanning)
        {
            set_final_chunk_out(m_chain_height, m_next_start_height, m_top_known_block_id, chunk_out);
            return;
        }

        if (!m_made_first_request)
        {
            // TODO: enable caller to set these
            m_http_client->set_server("127.0.0.1:18081", boost::optional<epee::net_utils::http::login>(), epee::net_utils::ssl_support_t::e_ssl_support_disabled);

            // request the first chunk from the daemon synchronously
            request_onchain_chunk(m_next_start_height, m_max_chunk_size, m_http_client, m_onchain_chunk_to_scan);
            m_made_first_request = true;
        }
        else
        {
            // wait for the async chunk request to complete
            if (!m_network_waiter.wait())
                throw std::runtime_error("Failed waiting for onchain chunk request");
        }
        cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response chunk_to_scan = std::move(m_onchain_chunk_to_scan);

        if (chunk_to_scan.current_height > 0)
            m_chain_height = chunk_to_scan.current_height;

        if (chunk_to_scan.blocks.size() == 0)
        {
            // no blocks to scan in this chunk, we should be done
            set_final_chunk_out(m_chain_height, m_next_start_height, m_top_known_block_id, chunk_out);
            return;
        }
        else
        {
            m_next_start_height = m_next_start_height + chunk_to_scan.blocks.size();

            // check if this chunk is the last chunk we need to scan
            if (m_next_start_height >= m_chain_height)
            {
                // we're finished scanning after we scan this last chunk
                m_finished_scanning = true;
            }
            else
            {
                // async request for the next chunk if this chunk isn't the last chunk
                m_tpool.submit(&m_network_waiter, [&]{
                    request_onchain_chunk(m_next_start_height, m_max_chunk_size, m_http_client, m_onchain_chunk_to_scan);
                }, true);
            }

            scan_legacy_chunk(m_tpool, m_local_scanner_waiter, chunk_to_scan, m_enote_finding_context, chunk_out);
            m_top_known_block_id = chunk_out.m_block_ids.back();
        }
    }
    /// try to get a scanning chunk for the unconfirmed txs in a ledger
    void get_unconfirmed_chunk(sp::EnoteScanningChunkNonLedgerV1 &chunk_out) override
    {
        m_enote_finding_context.get_unconfirmed_chunk(chunk_out);
    }
    /// stop the current scanning process (should be no-throw no-fail)
    void terminate_scanning() override { /* no-op */ }
    /// test if scanning has been aborted
    bool is_aborted() const override { return false; }

//member variables
private:
    /// finds chunks of enotes that are owned
    const EnoteFindingContextLedgerLegacy &m_enote_finding_context;

    bool m_made_first_request{false};
    bool m_finished_scanning{false};

    tools::threadpool &m_tpool = tools::threadpool::getInstance();
    tools::threadpool::waiter m_network_waiter;
    tools::threadpool::waiter m_local_scanner_waiter;

    cryptonote::COMMAND_RPC_GET_BLOCKS_FAST::response m_onchain_chunk_to_scan;

    std::uint64_t m_next_start_height{0};
    std::uint64_t m_max_chunk_size{0};
    std::uint64_t m_chain_height{static_cast<std::uint64_t>(-1)};
    rct::key m_top_known_block_id{rct::zero()};

    const std::unique_ptr<epee::net_utils::http::http_client_factory> m_http_client_factory = std::unique_ptr<epee::net_utils::http::http_client_factory>(new net::http::client_factory());
    const std::unique_ptr<epee::net_utils::http::abstract_http_client> m_http_client = m_http_client_factory->create();
};

std::string monero_utils::scan_chain(const std::string &legacy_spend_privkey_str, const std::string &legacy_view_privkey_str)
{
  // load keys
  /// spend key
  crypto::secret_key legacy_spend_privkey;
  crypto::public_key legacy_base_spend_pubkey_t;
  rct::key legacy_base_spend_pubkey;
  epee::string_tools::hex_to_pod(legacy_spend_privkey_str, legacy_spend_privkey);
  crypto::secret_key_to_public_key(legacy_spend_privkey, legacy_base_spend_pubkey_t);
  legacy_base_spend_pubkey = rct::pk2rct(legacy_base_spend_pubkey_t);
  /// view key
  crypto::secret_key legacy_view_privkey;
  epee::string_tools::hex_to_pod(legacy_view_privkey_str, legacy_view_privkey);

  const sp::RefreshLedgerEnoteStoreConfig refresh_config{
          .m_reorg_avoidance_depth = 1,
          .m_max_chunk_size = 1, // TODO: investigate why is this not being used in the scanning context? is it even necessary?
          .m_max_partialscan_attempts = 0
      };

  std::unordered_map<rct::key, cryptonote::subaddress_index> legacy_subaddress_map{};
  add_default_subaddresses(legacy_base_spend_pubkey, legacy_view_privkey, legacy_subaddress_map);

  const EnoteFindingContextLedgerLegacy enote_finding_context{
          legacy_base_spend_pubkey,
          legacy_subaddress_map,
          legacy_view_privkey
      };

  EnoteScanningContextLedgerMultithreaded enote_scanning_context{enote_finding_context};

  sp::mocks::SpEnoteStoreMockV1 user_enote_store{0, 3000000, 10};
  sp::mocks::EnoteStoreUpdaterMockLegacy enote_store_updater{
          legacy_base_spend_pubkey,
          legacy_spend_privkey,
          legacy_view_privkey,
          user_enote_store
      };

  sp::refresh_enote_store_ledger(refresh_config, enote_scanning_context, enote_store_updater);

  return user_enote_store.get_balance(
        {sp::SpEnoteOriginStatus::ONCHAIN, sp::SpEnoteOriginStatus::UNCONFIRMED},
        {sp::SpEnoteSpentStatus::SPENT_ONCHAIN, sp::SpEnoteSpentStatus::SPENT_UNCONFIRMED}).str();
}
