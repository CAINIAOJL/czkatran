#include "test.h"

#include <iostream>

using namespace std;
int main(int argc, char** argv) {
    cout << "sizeof of class x is " << sizeof(x) << endl;
    cout << "sizeof of class y is " << sizeof(y) << endl;
    cout << "sizeof of class z is " << sizeof(z) << endl;
    cout << "sizeof of class a is " << sizeof(a) << endl;
    cout << "aligenment is x: " << alignof(x) << endl;
    cout << "aligenment is y: " << __alignof__(y) << endl;
    cout << "aligenment is z: " << __alignof__(z) << endl;
    cout << "aligenment is a: " << __alignof__(a) << endl;
    cout << "&b::j = " << &b::j << endl;
    cout << "&b::y = " << &b::y << endl;
    cout << "&b::p = " << &b::p << endl;
    printf("&b::j = %p\n", &b::j);
    printf("&b::y = %p\n", &b::y);
    printf("&b::p = %p\n", &b::p);
}