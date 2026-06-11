export CC=clang-18
export CXX=clang++-18
# rm -rf build && cmake  -B build -S . && cmake --build build
rm -rf build && cmake -B build -S . && cmake --build build
#-DCMAKE_BUILD_TYPE=debug
