//------------------------------------------------------------------------------
//
//   Copyright 2019-2020 Fetch.AI Limited
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
//------------------------------------------------------------------------------

#include <iostream>
#include <sys/time.h>
#include "app_build.hpp"
#include "crypto_mcl.hpp"
#include "glow_dvrf.hpp"
using namespace fetch::consensus;

std::unordered_map<uint32_t, std::string> sigShares;

int main(int argc, char *argv[]) {
  double latency{0};
  bool networked{false};
  uint32_t threads{1};
  const uint32_t nbNodes{100};
  uint32_t threshold{67};
  uint32_t nbRounds{1};
  bool signMessages{false};
  uint32_t cryptoLib{4};

  struct timeval tv_start;
  gettimeofday(&tv_start, nullptr);

  try {
    fetch::consensus::Scheduler scheduler{threads};
    DKGEventObserver obs{nbNodes};
    std::vector<std::unique_ptr<fetch::consensus::AbstractDkgNode>> nodes;

    assert(cryptoLib==4);
    nodes = build<GlowDvrf<CryptoMcl>>(networked, latency, obs, nbNodes, threshold, scheduler,
                                       signMessages);

    gettimeofday(&obs.tv_init, nullptr);
    std::cout << "## Init takes " << (double)timeval_diff(tv_start, obs.tv_init) / 1000 << " ms for " << nbNodes << " nodes." << std::endl;
    obs.threshold = threshold;

    // Enable threshold signing
    for (uint32_t iv = 0; iv < nbNodes; ++iv) {
      nodes[iv]->enableThresholdSigning(nbRounds);
    }

    //SignaturesShare shares[nbNodes];
    for (uint32_t iv = 0; iv < nbNodes; ++iv) {
      nodes[iv]->sendSignatureShare();
    }

    scheduler.stop();
  } catch (std::exception &e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }
  return 0;
}
