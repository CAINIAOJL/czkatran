#pragma once

#include <folly/File.h>
#include <string>

#include "DataWriter.h"

namespace czkatran {

class FileWriter : public DataWriter {
    public:
        explicit FileWriter(const std::string& filename);

        void writeData(const void* ptr, std::size_t size) override;
        
        bool available(std::size_t size) override;

        bool restart() override; 

        bool stop() override;
    
    private:
        folly::File PcapFile_;
        std::string filename_;
};




}