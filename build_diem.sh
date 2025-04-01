#! /usr/bin/bash

git clone https://github.com/diem/diem.git
cd diem 
git checkout 94a8bca0f
./build
./scripts/dev_setup.sh
source ~/.cargo/env

cargo build -p diem-genesis-tool --release
cargo build -p diem-node --release
