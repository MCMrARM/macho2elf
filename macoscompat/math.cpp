#include <cmath>

extern "C" {

struct double2 {
    double sinval;
    double cosval;
};
struct double2 __sincos_stret(double v) {
    double2 ret;
    sincos(v, &ret.sinval, &ret.cosval);
    return ret;
}

}