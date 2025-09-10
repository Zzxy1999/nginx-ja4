# Nginx with SSL Fingerprinting Makefile
# =====================================

# 项目配置
PROJECT_NAME = nginx-ssl-fingerprint
NGINX_VERSION = 1.20.2
OPENSSL_VERSION = 1.1.1h

# 路径配置
PWD = $(shell pwd)
NGINX_DIR = $(PWD)/nginx-$(NGINX_VERSION)
OPENSSL_DIR = $(PWD)/openssl-$(OPENSSL_VERSION)
THIRD_MODULES_DIR = $(PWD)/third-modules
INSTALL_PREFIX = /usr/local/nginx
HOME_NGINX_DIR = $(HOME)/nginx

# 编译配置
CC_OPTS = -g -O0 -DNGX_DEBUG
OPENSSL_OPTS = -g -O0
JOBS = $(shell nproc)

# 默认目标
.PHONY: all
all: build

# 帮助信息
.PHONY: help
help:
	@echo "Nginx SSL Fingerprinting Build System"
	@echo "====================================="
	@echo ""
	@echo "Available targets:"
	@echo "  help        - Show this help message"
	@echo "  deps        - Check dependencies"
	@echo "  clean       - Clean build files"
	@echo "  configure   - Configure nginx build"
	@echo "  build       - Build nginx (configure + compile)"
	@echo "  install     - Install nginx (requires sudo)"
	@echo "  reinstall   - Clean + build + install"
	@echo "  setup-dirs  - Create necessary directories"
	@echo "  start       - Start nginx"
	@echo "  stop        - Stop nginx"
	@echo "  restart     - Restart nginx"
	@echo "  status      - Check nginx status"
	@echo "  test-config - Test nginx configuration"
	@echo "  logs        - Show error logs"
	@echo "  access-logs - Show access logs"
	@echo "  test        - Run tests"
	@echo ""
	@echo "Build configuration:"
	@echo "  NGINX_VERSION: $(NGINX_VERSION)"
	@echo "  OPENSSL_VERSION: $(OPENSSL_VERSION)"
	@echo "  INSTALL_PREFIX: $(INSTALL_PREFIX)"

# 检查依赖
.PHONY: deps
deps:
	@echo "Checking dependencies..."
	@which gcc >/dev/null || (echo "ERROR: gcc not found" && exit 1)
	@which make >/dev/null || (echo "ERROR: make not found" && exit 1)
	@which pcre-config >/dev/null || (echo "WARNING: pcre-devel not found, install with: yum install pcre-devel")
	@which zlib >/dev/null 2>&1 || (echo "WARNING: zlib-devel might be missing, install with: yum install zlib-devel")
	@[ -d "$(NGINX_DIR)" ] || (echo "ERROR: $(NGINX_DIR) not found" && exit 1)
	@[ -d "$(OPENSSL_DIR)" ] || (echo "ERROR: $(OPENSSL_DIR) not found" && exit 1)
	@[ -d "$(THIRD_MODULES_DIR)" ] || (echo "ERROR: $(THIRD_MODULES_DIR) not found" && exit 1)
	@echo "✓ Dependencies check passed"

# 创建必要的目录
.PHONY: setup-dirs
setup-dirs:
	@echo "Setting up directories..."
	@mkdir -p $(HOME_NGINX_DIR)/logs
	@mkdir -p $(HOME_NGINX_DIR)/cache/{client,proxy,fastcgi,uwsgi,scgi}_temp
	@echo "✓ Directories created"

# 清理编译文件
.PHONY: clean
clean:
	@echo "Cleaning build files..."
	@cd $(NGINX_DIR) && [ -f Makefile ] && make clean 2>/dev/null || true
	@cd $(OPENSSL_DIR) && [ -f Makefile ] && make clean 2>/dev/null || true
	@rm -f $(NGINX_DIR)/objs/nginx
	@echo "✓ Clean completed"

# 配置nginx
.PHONY: configure
configure: deps setup-dirs
	@echo "Configuring nginx..."
	@cd $(NGINX_DIR) && ./configure \
		--prefix=$(INSTALL_PREFIX) \
		--sbin-path=$(INSTALL_PREFIX)/sbin/nginx \
		--conf-path=$(INSTALL_PREFIX)/conf/nginx.conf \
		--error-log-path=$(HOME_NGINX_DIR)/logs/error.log \
		--http-log-path=$(HOME_NGINX_DIR)/logs/access.log \
		--with-debug \
		--with-cc-opt='$(CC_OPTS)' \
		--with-openssl-opt='$(OPENSSL_OPTS)' \
		--pid-path=$(HOME_NGINX_DIR)/nginx.pid \
		--lock-path=$(HOME_NGINX_DIR)/nginx.lock \
		--http-client-body-temp-path=$(HOME_NGINX_DIR)/cache/client_temp \
		--http-proxy-temp-path=$(HOME_NGINX_DIR)/cache/proxy_temp \
		--http-fastcgi-temp-path=$(HOME_NGINX_DIR)/cache/fastcgi_temp \
		--http-uwsgi-temp-path=$(HOME_NGINX_DIR)/cache/uwsgi_temp \
		--http-scgi-temp-path=$(HOME_NGINX_DIR)/cache/scgi_temp \
		--with-openssl=../openssl-$(OPENSSL_VERSION) \
		--user=www-data \
		--group=www-data \
		--with-file-aio \
		--with-threads \
		--with-http_addition_module \
		--with-http_auth_request_module \
		--with-http_dav_module \
		--with-http_flv_module \
		--with-http_gunzip_module \
		--with-http_gzip_static_module \
		--with-http_mp4_module \
		--with-http_realip_module \
		--with-http_secure_link_module \
		--with-http_ssl_module \
		--with-http_stub_status_module \
		--with-http_sub_module \
		--with-http_v2_module \
		--with-mail \
		--with-mail_ssl_module \
		--with-stream \
		--with-stream_ssl_module \
		--add-module=../third-modules/nginx-ssl-fingerprint
	@echo "✓ Configuration completed"

# 编译nginx
.PHONY: compile
compile:
	@echo "Compiling nginx..."
	@cd $(NGINX_DIR) && make -j$(JOBS)
	@echo "✓ Compilation completed"

# 构建nginx (配置 + 编译)
.PHONY: build
build: configure compile
	@echo "✓ Build completed successfully"
	@echo "Binary: $(NGINX_DIR)/objs/nginx"

# 安装nginx
.PHONY: install
install: build
	@echo "Installing nginx..."
	@cd $(NGINX_DIR) && sudo make install
	@echo "✓ Installation completed"
	@echo "Nginx installed to: $(INSTALL_PREFIX)"

# 重新安装
.PHONY: reinstall
reinstall: clean install
	@echo "✓ Reinstallation completed"

# 启动nginx
.PHONY: start
start:
	@echo "Starting nginx..."
	@sudo $(INSTALL_PREFIX)/sbin/nginx
	@echo "✓ Nginx started"

# 停止nginx
.PHONY: stop
stop:
	@echo "Stopping nginx..."
	@sudo $(INSTALL_PREFIX)/sbin/nginx -s quit || true
	@echo "✓ Nginx stopped"

# 重启nginx
.PHONY: restart
restart: stop start
	@echo "✓ Nginx restarted"

# 重载配置
.PHONY: reload
reload:
	@echo "Reloading nginx configuration..."
	@sudo $(INSTALL_PREFIX)/sbin/nginx -s reload
	@echo "✓ Configuration reloaded"

# 检查nginx状态
.PHONY: status
status:
	@echo "Nginx status:"
	@ps aux | grep "[n]ginx" || echo "Nginx is not running"
	@echo ""
	@echo "Listening ports:"
	@netstat -tlnp 2>/dev/null | grep nginx || echo "No nginx ports found"

# 测试配置文件
.PHONY: test-config
test-config:
	@echo "Testing nginx configuration..."
	@sudo $(INSTALL_PREFIX)/sbin/nginx -t
	@echo "✓ Configuration test passed"

# 查看错误日志
.PHONY: logs
logs:
	@echo "=== Error Logs ==="
	@tail -f $(HOME_NGINX_DIR)/logs/error.log

# 查看访问日志
.PHONY: access-logs
access-logs:
	@echo "=== Access Logs ==="
	@tail -f $(HOME_NGINX_DIR)/logs/access.log

# 运行测试
.PHONY: test
test:
	@echo "Running tests..."
	@cd $(PWD) && [ -f test_comprehensive.c ] && gcc -o test_comprehensive test_comprehensive.c && ./test_comprehensive || echo "No tests found"
	@cd $(PWD) && [ -f test_advanced.c ] && gcc -o test_advanced test_advanced.c && ./test_advanced || echo "No advanced tests found"
	@echo "✓ Tests completed"

# 显示版本信息
.PHONY: version
version:
	@echo "Project: $(PROJECT_NAME)"
	@echo "Nginx: $(NGINX_VERSION)"
	@echo "OpenSSL: $(OPENSSL_VERSION)"
	@[ -f "$(INSTALL_PREFIX)/sbin/nginx" ] && $(INSTALL_PREFIX)/sbin/nginx -v || echo "Nginx not installed"

# 开发模式 - 快速编译测试
.PHONY: dev
dev: compile
	@echo "Development build completed"
	@echo "Binary: $(NGINX_DIR)/objs/nginx"
	@echo "Run with: sudo $(NGINX_DIR)/objs/nginx -p $(PWD) -c conf/nginx.conf"

# 清理所有生成文件
.PHONY: distclean
distclean: clean
	@echo "Deep cleaning..."
	@rm -rf $(NGINX_DIR)/objs
	@rm -f test_comprehensive test_advanced
	@echo "✓ Deep clean completed"

# 显示配置信息
.PHONY: info
info:
	@echo "Build Information:"
	@echo "=================="
	@echo "Project:     $(PROJECT_NAME)"
	@echo "Nginx:       $(NGINX_VERSION)"
	@echo "OpenSSL:     $(OPENSSL_VERSION)"
	@echo "Install:     $(INSTALL_PREFIX)"
	@echo "Home dir:    $(HOME_NGINX_DIR)"
	@echo "Jobs:        $(JOBS)"
	@echo "CC opts:     $(CC_OPTS)"
	@echo ""
	@echo "Paths:"
	@echo "======"
	@echo "Nginx src:   $(NGINX_DIR)"
	@echo "OpenSSL src: $(OPENSSL_DIR)"
	@echo "Modules:     $(THIRD_MODULES_DIR)"
