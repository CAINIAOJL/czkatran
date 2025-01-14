#include <optional>
#include <iostream>
#include <fmt/core.h>
#include <folly/AtomicHashArray.h>
int main() {
    std::optional<bool> routedThroughGlobalLru{std::nullopt};
    routedThroughGlobalLru = true;
    // 检查optional对象是否有值
    if (routedThroughGlobalLru.has_value()) {
        std::cout << "Routed through global LRU: " << routedThroughGlobalLru.value() << std::endl;
    } else {
        std::cout << "Routed through global LRU value is not set." << std::endl;
    }

    // 可以设置值并再次检查
    routedThroughGlobalLru = true;
    if (routedThroughGlobalLru.has_value()) {
        std::cout << "Routed through global LRU: " << routedThroughGlobalLru.value() << std::endl;
    }

    std::cout << fmt::format(
            "Test: {:60} result: {}", "我是测试样子", "\033[31mFailed\033[0m"
        ) << std::endl;
    fmt::print("Слава Україні!\n");
    return 0;
}