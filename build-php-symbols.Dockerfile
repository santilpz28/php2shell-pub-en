# Imagen de compilacion para PHP 8.2.34 CON SIMBOLOS (no stripped).
# Necesaria para la PoC: permite calcular el offset zif_system - zval_ptr_dtor
# y entender el comportamiento real del binario.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      autoconf bison re2c pkg-config \
      gcc g++ make \
      libxml2-dev libssl-dev libcurl4-openssl-dev libsqlite3-dev \
      libonig-dev libreadline-dev zlib1g-dev libargon2-dev \
      libssl-dev libsodium-dev libzip-dev \
      ca-certificates curl xz-utils file \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY .cache/php-8.2.34.tar.gz /build/

RUN tar xzf php-8.2.34.tar.gz && cd php-8.2.34 && \
    ./configure \
      --prefix=/usr/local/php-symbols \
      --enable-session \
      --disable-cgi \
      --disable-phpdbg \
      --without-pear \
      --enable-cli \
      --with-openssl \
      --disable-opcache \
    && make -j"$(nproc)" \
    && make install \
    && echo "BUILD OK"

# El binario conserva la tabla de simbolos (no se strip-ea)
CMD ["/usr/local/php-symbols/bin/php", "-v"]
