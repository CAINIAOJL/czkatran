#include "FileWriter.h"

#include <folly/FileUtil.h>
#include <glog/logging.h>

namespace czkatran {

FileWriter::FileWriter(const std::string& filename)
    : PcapFile_(filename.c_str(), O_RDWR | O_CREAT | O_TRUNC) {
    filename_ = filename;
}

void FileWriter:: writeData(const void* ptr, std::size_t size) {
    auto isok = folly::writeFull(PcapFile_.fd(), ptr, size);
    if(isok < 0) {
        LOG(ERROR) << "Error writing to pcap file " << filename_;
    } else {
        writtenBytes_ += size;
    }
}

bool FileWriter:: available(std::size_t size) {
    return true;
}

bool FileWriter::stop() {
    PcapFile_.closeNoThrow();
    return true;
}

bool FileWriter::restart() {
    PcapFile_.closeNoThrow();
    PcapFile_ = folly::File(filename_.c_str(), O_RDWR | O_CREAT | O_TRUNC);
    return true;
}


}