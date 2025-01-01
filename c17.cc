#include <optional>
#include <iostream>

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

    return 0;
}