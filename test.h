#pragma once

//#pragma pack(1)
class x {

};
//#pragma pack()
//#pragma pack(1)
class y : public virtual x {

};
//#pragma pack()
//#pragma pack(1)
class z : public virtual x {

};
//#pragma pack()
//#pragma pack(1)
class a : public y, public z {

};
//#pragma pack()

class b {
    public:
        virtual ~b();
        static b Bob;
        float j, y, p;
};