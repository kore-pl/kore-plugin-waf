# kore-plugin-waf 构建入口：build / dist / check / clean。
SHELL := /bin/bash

ID := waf
BIN := bin/$(ID)
DIST := dist
VERSION := $(shell sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' info.json | head -n 1)
PACKAGE := $(DIST)/$(ID)-$(VERSION).tar.gz

.PHONY: build dist check clean

# 静态构建：G-16 兼容性基线（CGO_ENABLED=0 + GOAMD64=v1 + trimpath + -s -w）。
build:
	CGO_ENABLED=0 GOAMD64=v1 go build -trimpath -buildvcs=false -ldflags="-s -w" -o $(BIN) .

# 确定性打包：info.json（回填 size_bytes）+ bin/waf + SHA256SUMS。
# 显式列条目（info.json bin SHA256SUMS），无 ./ 根条目，无 web/ 前端。
# 归档参数：--sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner + gzip -9n。
dist: build
	@set -eo pipefail; \
	rm -rf $(DIST)/stage $(PACKAGE) $(PACKAGE).sha256; \
	mkdir -p $(DIST)/stage/bin; \
	cp $(BIN) $(DIST)/stage/bin/$(ID); \
	cp info.json $(DIST)/stage/info.json; \
	chmod 0755 $(DIST)/stage/bin; \
	chmod 0755 $(DIST)/stage/bin/$(ID); \
	chmod 0644 $(DIST)/stage/info.json; \
	( cd $(DIST)/stage && sha256sum info.json bin/$(ID) > SHA256SUMS ); \
	chmod 0644 $(DIST)/stage/SHA256SUMS; \
	# 迭代收敛 size_bytes 到 gzip 后实际包体大小（偏差 ≤10%）。\
	size=0; \
	for _ in 1 2 3; do \
		tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - -C $(DIST)/stage info.json bin SHA256SUMS | gzip -9n > $(PACKAGE); \
		actual=$$(stat -c%s $(PACKAGE)); \
		if [ "$$actual" = "$$size" ]; then break; fi; \
		size=$$actual; \
		sed "s/\"size_bytes\": [0-9]*/\"size_bytes\": $$size/" info.json > $(DIST)/stage/info.json; \
		chmod 0644 $(DIST)/stage/info.json; \
		( cd $(DIST)/stage && sha256sum info.json bin/$(ID) > SHA256SUMS ); \
		chmod 0644 $(DIST)/stage/SHA256SUMS; \
	done; \
	( cd $(DIST) && sha256sum $(ID)-$(VERSION).tar.gz > $(ID)-$(VERSION).tar.gz.sha256 ); \
	rm -rf $(DIST)/stage; \
	echo "打包完成: $(PACKAGE)"

# 门禁：gofmt（有输出即失败）→ go vet → go test。
check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt 需要格式化："; echo "$$out"; exit 1; fi; echo "gofmt: clean"
	go vet ./...
	go test -timeout 200s ./...

clean:
	rm -rf bin dist
	rm -f go.work.sum
