
.PHONY: all clean

all: test

nginx-1.9.2/objs/ngx_auto_config.h:
	curl -s http://nginx.org/download/nginx-1.9.2.tar.gz -o nginx-1.9.2.tar.gz
	tar xzf nginx-1.9.2.tar.gz
	mkdir -p logs
	cd nginx-1.9.2 && \
		./configure --with-http_ssl_module --add-module=../.. \
			--prefix=$$PWD/..

nginx: nginx-1.9.2/objs/ngx_auto_config.h ../src/*.c ../src/*.h
	cd nginx-1.9.2 && make
	cp nginx-1.9.2/objs/nginx $@

conf/nginx.conf:
	python setup-test.py

test: nginx conf/nginx.conf
	./test-conf.sh && ./test-handler.sh

clean:
	rm -rf nginx nginx-1.9.2 conf/apikey.properties conf/nginx.conf


