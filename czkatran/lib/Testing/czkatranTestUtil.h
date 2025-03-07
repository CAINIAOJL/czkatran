#pragma once
//------------------------------------2025-2-15-------------------------------
//--------------------------√
#include <string>
#include <vector>
//#include "/home/jianglei/czkatran/czkatran/lib/czkatranLb.h"
//#include "/home/jianglei/czkatran/czkatran/lib/Testing/czkatranTestProvision.h"

//#include "/home/cainiao/czkatran/czkatran/lib/czkatranLb.h"
//#include "/home/cainiao/czkatran/czkatran/lib/Testing/czkatranTestProvision.h"

#include "/home/jianglei/czkatran/czkatran/lib/czkatranLb.h"
#include "/home/jianglei/czkatran/czkatran/lib/czkatranLbStructs.h"
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