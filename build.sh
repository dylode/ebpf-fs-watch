#!/bin/bash

cd build
cmake ../
make watch-ebpf
make watch-ebpf-skel
make ebpf-fs-watch