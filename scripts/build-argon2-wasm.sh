#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source_dir="$repo_root/web/argon2-reference"
asset_dir="$repo_root/web/vendor/guardian-argon2"
image='emscripten/emsdk:4.0.10@sha256:90b757eb11fa9a0e3ce4d2d9f76d932a56018e4accc37b5a28b2783751e60eb7'
runtime_name=argon2id-runtime-1b3aa08f6d118ad6.js
wasm_name=argon2id-4507b469b9b103a5.wasm
worker_name=argon2id-worker-db57362e2dddfb66.js
runtime_sha=1b3aa08f6d118ad69a81bfce34d2d24ab0f80f5111542cbae3382b279b3291f9
wasm_sha=4507b469b9b103a58ed72905a306b1dab90dd07235c4f9b05e818ee77a300865
worker_sha=db57362e2dddfb6604b942ff3108619cc18d332368b6bdbcd00fd23738d6c29b

tmp_dir=$(mktemp -d)
trap 'rm -rf -- "$tmp_dir"' EXIT

compile=(
  /src/src/argon2.c /src/src/core.c /src/src/encoding.c /src/src/ref.c
  /src/src/blake2/blake2b.c -I/src/include -I/src/src
  -DARGON2_NO_THREADS -O3 -flto
  -sENVIRONMENT=worker -sMODULARIZE=1 -sEXPORT_NAME=GuardianArgon2Module
  '-sEXPORTED_FUNCTIONS=["_argon2_hash","_malloc","_free"]'
  '-sEXPORTED_RUNTIME_METHODS=["HEAPU8"]'
  -sFILESYSTEM=0 -sASSERTIONS=0 -sALLOW_MEMORY_GROWTH=1
  -sINITIAL_MEMORY=41943040 -sMAXIMUM_MEMORY=50331648 -sSTACK_SIZE=65536
  -o /out/argon2id.js
)

if command -v emcc >/dev/null 2>&1; then
  native_compile=("${compile[@]}")
  for i in "${!native_compile[@]}"; do
    case ${native_compile[$i]} in
      /src/*)
        native_compile[$i]="$source_dir/${native_compile[$i]#/src/}"
        ;;
      -I/src/*)
        native_compile[$i]="-I$source_dir/${native_compile[$i]#-I/src/}"
        ;;
      /out/*)
        native_compile[$i]="$tmp_dir/${native_compile[$i]#/out/}"
        ;;
    esac
  done
  emcc "${native_compile[@]}"
else
  docker run --rm \
    -v "$source_dir:/src:ro" \
    -v "$tmp_dir:/out" \
    "$image" emcc "${compile[@]}"
fi

printf '%s  %s\n' "$runtime_sha" "$tmp_dir/argon2id.js" | sha256sum --check --status
printf '%s  %s\n' "$wasm_sha" "$tmp_dir/argon2id.wasm" | sha256sum --check --status
printf '%s  %s\n' "$worker_sha" "$asset_dir/$worker_name" | sha256sum --check --status
cmp "$tmp_dir/argon2id.js" "$asset_dir/$runtime_name"
cmp "$tmp_dir/argon2id.wasm" "$asset_dir/$wasm_name"

wasm_size=$(wc -c < "$asset_dir/$wasm_name")
if (( wasm_size > 307200 )); then
  echo "Argon2id WASM is ${wasm_size} bytes; maximum is 307200" >&2
  exit 1
fi
echo "Argon2id browser assets are reproducible; WASM size: ${wasm_size} bytes"
