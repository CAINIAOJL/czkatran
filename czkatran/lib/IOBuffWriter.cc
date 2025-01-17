#include "IOBuffWriter.h"

#include <string>

namespace czkatran {

IOBuffWriter::IOBuffWriter(folly::IOBuf* iobuf) :
                iobuf_(iobuf)
{

}

void IOBuffWriter:: writeData(const void* ptr, std::size_t size) {
    ::memcpy(iobuf_->writableTail(), ptr, size);
    iobuf_->append(size);
}

bool IOBuffWriter:: available(std::size_t size) {
    return iobuf_->tailroom() >= size;
}

bool IOBuffWriter:: restart() {
    iobuf_->clear();
    return true;
}



}