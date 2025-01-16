#pragma once

#include <cstddef>


namespace czkatran {

class DataWriter {
    public:
        virtual ~DataWriter() {}

        /**
         * @brief Write data to the output stream.
         * @param ptr Pointer to the data to be written.
         * @param size Size of the data to be written.
         */
        virtual void writeData(const void* ptr, std::size_t size) = 0;

        virtual void writeHeader(const void* ptr, std::size_t size) {
            writeData(ptr, size);
        }

        /**
         * @brief 对于size要写的内容，是否可以写入
         * @param size 要写的内容的大小
         * @return 是否可以写入
         */
        virtual bool available(std::size_t size) = 0;

        /**
         * @brief 重置输入流
         * @return 是否成功重置
         */
        virtual bool restart() = 0;

        /**
         * @brief 停止输入流
         * @return 是否成功停止
         */
        virtual bool stop() = 0;

        std::size_t writtenBytes() {
            return writtenBytes_;
        }

    protected:
        std::size_t writtenBytes_ {0};
};

}