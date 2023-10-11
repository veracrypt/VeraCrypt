# wolfSSL as crypto provider for VeraCrypt

[wolfCrypt](https://www.wolfssl.com/products/wolfcrypt/) is wolfSSL's cutting edge crypto engine and a 
potential FIPS solution for users of VeraCrypt. Follow the steps below to setup VeraCrypt with wolfCrypt. 

## Building wolfSSL

Clone wolfSSL and build it as shown below.

```
git clone https://github.com/wolfssl/wolfssl && cd wolfssl
./autogen.sh
./configure --enable-xts CFLAGS="-DNO_OLD_WC_NAMES"
make
sudo make install
```

## Building VeraCrypt with wolfSSL

Build VeraCrypt with the `WOLFCRYPT` command line option.

```
make WXSTATIC=1 wxbuild && make WXSTATIC=1 clean && make WXSTATIC=1 WOLFCRYPT=1 && make WXSTATIC=1 WOLFCRYPT=1 package
```

