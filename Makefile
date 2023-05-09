all: wasm_debug

WASM_PKG = wasm.tar.gz
lib_files = ./$(WASM_PKG)

wasm_debug:
	cd wasm && wasm-pack build

wasm_release:
	cd wasm && wasm-pack build --release

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
