#include "CHHelper.h"

#include "MaglevHash.h"
#include "MaglevHashV2.h"


namespace czkatran {
    std::unique_ptr<ConsistentHashing> CHFactory::make(HashFunction func) {
        switch (func) {
            case HashFunction::Maglev:
                return std::make_unique<MaglevHash>();
            case HashFunction::Maglev2:
                return std::make_unique<MaglevHashV2>();
            default:
                return std::make_unique<MaglevHash>();
        }
    }
}