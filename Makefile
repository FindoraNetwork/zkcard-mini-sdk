all: build wasm_node

WASM_PKG = wasm.tar.gz
lib_files = ./$(WASM_PKG)

wasm_node:
	cd wasm && wasm-pack build --target nodejs

wasm_web:
	cd wasm && wasm-pack build --target web

wasm_pack:
	- tar -zcpf $(WASM_PKG) wasm/pkg

clean:
	cargo clean
	- rm -rf wasm/pkg
	- rm -f wasm.tar.gz

build:
	cargo build

build_release:
	cargo build --release

fmt:
	cargo fmt

update:
	git submodule update --recursive --init
	rustup update stable
	cargo update
