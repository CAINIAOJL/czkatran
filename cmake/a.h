#pragma once

namespace cz {

class a {
    public:
        a(int x, int y, int z) : x(x), y(y), z(z) {}

        int get_sum() const;
    private:
        int x;
        int y;
        int z;
};
}