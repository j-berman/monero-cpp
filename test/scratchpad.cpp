#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include "utils/monero_utils.h"

using namespace std;

/**
 * Scratchpad main entry point.
 */
int main(int argc, const char* argv[]) {

  // configure logging
  mlog_configure("log_cpp_scratchpad.txt", true);
  mlog_set_log_level(1);
  //MINFO("logging info!!!");
  //MWARNING("logging a warning!!!");
  //MERROR("logging an error!!!");

  // print header
  MINFO("===== Scratchpad =====");
  for (int i = 0; i < argc; i++) {
    MINFO("Argument" << i << ": " << argv[i]);
  }

  // load block bin from disk (could be a network request)
  std::ifstream file("./test/test_getblocks.bin");
  std::stringstream bin;
  bin << file.rdbuf();
  file.close();

  const string priv_spend_key = "00a2b863df07d1a892f4271bfd973f54ad0f43cb3f5e5d55301a7dd93d85e108";
  const string pub_spend_key = "e7d58992d9b18b87e6bcf24db488231343cfe1e7731aea98898f99c0681808d2";
  const string priv_view_key = "33107cd37938b58c2a6929b3530c2fc7628601446f9dc5af28ed82b736c6050a";

  monero_utils::spends_and_receives_t spends_and_receives = monero_utils::identify_spends_and_receives(bin.str(), priv_spend_key, priv_view_key);
  for (const auto &spend_or_receive : spends_and_receives)
  {
    MINFO("******************************************************************************************");
    MINFO("We " << (std::get<0>(spend_or_receive) ? "spent" : "received") << " an enote!");
    MINFO("Tx id:             " << std::get<1>(spend_or_receive));
    MINFO("Stealth address:   " << std::get<2>(spend_or_receive));
    MINFO("Block height:      " << std::get<3>(spend_or_receive));
    MINFO("Amount:            " << std::get<4>(spend_or_receive));
    MINFO("******************************************************************************************");
  }

  /*

    2022-12-31 23:26:05.339	I ******************************************************************************************
    2022-12-31 23:26:05.339	I We received an enote!
    2022-12-31 23:26:05.339	I Tx id:             a50911c7d477da58b9d7eb5ca65147d2a84d7f5db033c80e8c8e05dde5f75104
    2022-12-31 23:26:05.339	I Stealth address:   9defc5f2dae8ff2dbbd91f470a0a9b9b0adde4560b9cda1b034ae119948aee0f
    2022-12-31 23:26:05.339	I Block height:      2815
    2022-12-31 23:26:05.339	I Amount:            3000000000000
    2022-12-31 23:26:05.339	I ******************************************************************************************
    2022-12-31 23:26:05.339	I ******************************************************************************************
    2022-12-31 23:26:05.339	I We spent an enote!
    2022-12-31 23:26:05.339	I Tx id:             1225488ca1e9563a7280275d827187bc5a0846a1014c618e0a507bea61b86c2f
    2022-12-31 23:26:05.339	I Stealth address:   9defc5f2dae8ff2dbbd91f470a0a9b9b0adde4560b9cda1b034ae119948aee0f
    2022-12-31 23:26:05.339	I Block height:      2859
    2022-12-31 23:26:05.339	I Amount:            3000000000000
    2022-12-31 23:26:05.339	I ******************************************************************************************
    2022-12-31 23:26:05.339	I ******************************************************************************************
    2022-12-31 23:26:05.339	I We received an enote!
    2022-12-31 23:26:05.339	I Tx id:             1225488ca1e9563a7280275d827187bc5a0846a1014c618e0a507bea61b86c2f
    2022-12-31 23:26:05.339	I Stealth address:   748009e56373df52a671a112b82393f12185376f14823f6130dc81c4ea9956af
    2022-12-31 23:26:05.339	I Block height:      2859
    2022-12-31 23:26:05.339	I Amount:            1998184400000
    2022-12-31 23:26:05.339	I ******************************************************************************************

  */

  std::string balance = monero_utils::scan_chain(priv_spend_key, priv_view_key);
  MINFO("Our total balance: " << balance);

  /*

    2023-01-12 10:13:18.677	I Our total balance: 1998184400000

  */
}
