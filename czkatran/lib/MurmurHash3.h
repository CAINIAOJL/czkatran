#pragma once


#include <stdint.h>

namespace czkatran {

    uint16_t MurmuHash3_x64_64(const uint16_t& A, const uint16_t& B, const uint32_t seed);
}