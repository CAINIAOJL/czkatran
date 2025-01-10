#pragma once

#include <string>


namespace folly {
    class IOBuf;
}


namespace czkatran {

class Base64Helpers {
    public:
        /**
         * @param buf the folly::IOBuf wanted to be encoded in base64 format
         * @return the base64 encoded string
         */
        static std::string base64Encode(folly::IOBuf* buf);

        /**
         * @param encode the base64 encoded string
         * @return the decoded string
         */
        static std::string base64Decode(std::string encode);
};
}