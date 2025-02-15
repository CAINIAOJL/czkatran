#pragma once
//------------------------------------2025-2-15-------------------------------
//--------------------------√
#include <string>
#include <vector>
#include "czkatranLb.h"
#include "czkatranTestProvision.h"


namespace czkatran {
namespace testing {

bool testSimulator(czkatran::czKatranLb& lb);

czkatranTestParam createDefaultTestParam(TestMode testMode);

czkatranTestParam createTPRTestParam();

czkatranTestParam createUdpStableRtTestParam();
 
}
}
//------------------------------------2025-2-15-------------------------------
//--------------------------√