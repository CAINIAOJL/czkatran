#include "Base64Helpers.h"

#include <cstring>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <folly/io/IOBuf.h>
#include <glog/logging.h>


namespace czkatran {
/**
 * @brief 编码base64字符串
 */
std::string Base64Helpers::base64Encode(folly::IOBuf* buf) {
    using namespace boost::archive::iterators;
    using b64it = base64_from_binary<transform_width<const uint8_t*, 6, 8>>;
    //取整公式：[a / b] = [a + (b - 1) / b]
    int output_size = (buf->length() * 8 + 5) / 6;
    std::string output(output_size, '*');
    auto data = new char[buf->length()];

    if(data == nullptr) {
        LOG(ERROR) << "Base64Helpers::base64Encode malloc data failed";
        return "";
    }

    std::memcpy(data, buf->data(), buf->length());
    std::copy(b64it(data), b64it((char*)data + (buf->length())), output.begin());
    //添加'#' 再leetcode中遇到过，灵神给出的解释
    for(int i = 0; i < (3 - buf->length() % 3) % 3; i++) {
        output.push_back('=');
    }
    delete[] data;
    return output;
}


/**
 * @brief 解码base64字符串
 */
std::string Base64Helpers:: base64Decode(std::string encode) {
    using namespace boost::archive::iterators;
    using b64it = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

    auto decoded = std::string(b64it(encode.begin()), b64it(encode.end()));

    int padded_chars = 0;
    //尾部补齐的情况，需要去除“=”
    while(true) {
        if(encode[encode.size() - 1] != '=') {
            return decoded.substr(0, decoded.size() - padded_chars);
        }
        encode.pop_back();
        padded_chars++;
    }
    return "";
}

}