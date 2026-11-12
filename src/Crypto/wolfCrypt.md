# wolfSSL as crypto provider for VeraCrypt

[wolfCrypt](https://www.wolfssl.com/products/wolfcrypt/) is an optional, unsupported
crypto backend contributed by wolfSSL. Standard VeraCrypt builds do not enable it.
Using this backend does not by itself make VeraCrypt a FIPS-validated application.

## Building wolfSSL

Use wolfSSL 5.9.2 or later and build it as shown below. VeraCrypt initializes the
provider's PBKDF2 iteration ceiling to support its full PIM range and treats
derivation failures as errors.

```
git clone https://github.com/wolfssl/wolfssl && cd wolfssl
./autogen.sh
./configure --enable-xts --enable-pwdbased CFLAGS="-DNO_OLD_WC_NAMES"
make
sudo make install
```

## Building VeraCrypt with wolfSSL

Pass `WOLFCRYPT=1` on the `make` command line to build VeraCrypt with wolfCrypt.
Leaving it unset or setting `WOLFCRYPT=0` selects the standard backend. Clean
before switching backends.

```
make WXSTATIC=1 wxbuild && make WXSTATIC=1 clean && make WXSTATIC=1 WOLFCRYPT=1 && make WXSTATIC=1 WOLFCRYPT=1 package
```

