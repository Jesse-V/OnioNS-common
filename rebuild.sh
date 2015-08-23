#!/bin/sh

echo "Re-styling code...        ----------------------------------------------"

# make the code-style consistent
for f in $(find src/ -type f -name "*.c*" | grep -v "libs"); do
   clang-format-3.6 -style="{BasedOnStyle: chromium, BreakBeforeBraces: Allman, MaxEmptyLinesToKeep: 3}" -i $f
done
# AlignConsecutiveAssignments: true
for f in $(find src/ -type f -name "*.h*" | grep -v "libs"); do
   clang-format-3.6 -style="{BasedOnStyle: chromium, BreakBeforeBraces: Allman, MaxEmptyLinesToKeep: 3}" -i $f
done

echo "Preparing build...        ----------------------------------------------"

export CXX=/usr/bin/clang++
export CC=/usr/bin/clang

mkdir -p build/
cd build
cmake ../src # -DCMAKE_BUILD_TYPE=Debug

echo "Compiling...              ----------------------------------------------"
if (make -j $(grep -c ^processor /proc/cpuinfo)) then
  echo "Static analysis...        ----------------------------------------------"
  cd ..
  find src -type f -follow -print | cppcheck -i "src/assets" -i "src/libs" -i "src/crypto" --enable=all --platform=unix64 --inconclusive --file-list=-
else
  rm -f onions-common
  cd ..
fi
