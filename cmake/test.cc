#include "a.h"
#include "b.h"
#include "c.h"
#include <iostream>


int main() {
    cz::a a1(1, 2, 3);
    cz::b b1(4, 5, 6);
    cz::c c1(7, 8, 9);
    
    std::cout << a1.get_sum() << std::endl;
    std::cout << b1.get_sum() << std::endl;
    std::cout << c1.get_sum() << std::endl;

    return 0;

}