#!/bin/bash
echo "Compiling custom C NTT Backend for Linux/macOS..."
gcc -O3 -shared -fPIC -o ntt.so ntt.c
if [ $? -ne 0 ]; then
    echo "[ERROR] Compilation failed!"
    exit 1
fi
echo "[SUCCESS] ntt.so compiled successfully!"
