#pragma once

namespace cz {

class b {
    public:
        b(int x, int y, int z) : x(x), y(y), z(z) {}

        int get_sum() const;
    private:
        int x;
        int y;
        int z;
};
}