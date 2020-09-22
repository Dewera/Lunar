mkdir bin\x86
mkdir bin\x64
cmake -A Win32 -B bin\x86
cmake -A x64 -B bin\x64
cmake --build bin\x86 --config Release
cmake --build bin\x64 --config Release