#!/bin/bash

set -e

if [[ ! -d Build ]]; then
	mkdir -p Build
fi

pushd Build
	cmake -DCMAKE_C_FLAGS=-m32 -DCMAKE_CXX_FLAGS=-m32 -DCMAKE_SHARED_LINKER_FLAGS=-m32 ../
	make
popd

echo -e "\nLinux server binary built!"
