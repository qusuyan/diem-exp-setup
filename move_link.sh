#! /bin/bash
DIEM_PATH=$1
OUT_DIR=$2

for filename in ${DIEM_PATH}/diem-move/diem-framework/DPN/releases/artifacts/current/build/MoveStdlib/bytecode_modules/*.mv; do
    ln $filename ${OUT_DIR}
done

for filename in ${DIEM_PATH}/diem-move/diem-framework/DPN/releases/artifacts/current/build/DiemCoreFramework/bytecode_modules/*.mv; do
    ln $filename ${OUT_DIR}
done
