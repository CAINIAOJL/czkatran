#pragma once

#include <folly/io/IOBuf.h>
#include <memory>
#include <string>


#include "DataWriter.h"

namespace czkatran {

class IOBuffWriter : public DataWriter {
    public:
        explicit IOBuffWriter(folly::IOBuf* iobuf);

        void writeData(const void* ptr, std::size_t size) override;

        bool available(std::size_t size) override;

        bool restart() override;

        bool stop() override {
            return true;
        }

    private:
        folly::IOBuf* iobuf_;

};

}