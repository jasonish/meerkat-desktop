all:

fmt:
	npx prettier -w .
	cd src-tauri && cargo fmt
