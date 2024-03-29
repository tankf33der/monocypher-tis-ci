#include <stdlib.h>
#include <stdio.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

typedef uint8_t u8;

#define ARRAY(name, size) \
    u8 name[size]; \
    for(size_t i = 0; i < size; i++) name[i] = i;

void p1305(void) {
    ARRAY(mac, 16);
    ARRAY(key, 32);
    ARRAY(in,  64);
    for(size_t i = 0; i < 64; i++)
        crypto_poly1305(mac, in, i, key);
}

void blake2b(void) {
    ARRAY(hash, 64);
    ARRAY(key,  64);
    ARRAY(in,   143);

    for(size_t h = 0; h < 64; h += 8)
        for(size_t k = 0; k < 64; k += 8)
            for(size_t i = 0; i < 143; i += 8)
                crypto_blake2b_general(hash, h, key, k, in, i);
}

void verify(void) {
    ARRAY(a, 64);
    ARRAY(b, 64);
    crypto_verify16(a, b);
    crypto_verify32(a, b);
    crypto_verify64(a, b);
}

void wipe(void) {
    ARRAY(a, 64);
    for(size_t i = 0; i < 64; i++)
        crypto_wipe(a, i);
}

void lock_unlock(void) {
    ARRAY(mac,   16);
    ARRAY(enc,   64);
    ARRAY(txt,   64);
    ARRAY(key,   33);
    ARRAY(nonce, 25);
    for(size_t i = 0; i < 64; i++) {
        crypto_lock  (mac, enc, key, nonce, txt, i);
        crypto_unlock(txt, key, nonce, mac, enc, i);
    }
}

void argon(void) {
    ARRAY(hash, 16);
    ARRAY(wrk,  16384); // 16 * 1024
    ARRAY(pwd,  16);
    ARRAY(key,  16);
    ARRAY(slt,  16);
    ARRAY(ad,   16);
    crypto_argon2i_general(hash, 16, wrk, 16, 4, pwd, 16, slt, 16, key, 16, ad, 16);
}

void key_exchange(void) {
    ARRAY(shd, 32);
    ARRAY(key, 32);
    // crypto_key_exchange_public_key is crypto_x25519_public_key
    crypto_key_exchange(shd, key, key);
}

void sign_check(void) {
    ARRAY(hash, 64);
    ARRAY(key,  32);
    ARRAY(pub,  32);
    ARRAY(in,   32);
    crypto_sign_public_key(pub, key);
    crypto_sign(hash, key, 0, in, 32);
    crypto_check(hash, pub, in, 32);
}

void from_eddsa(void) {
    ARRAY(shr, 32);
    ARRAY(key, 32);
    ARRAY(pub, 32);
    crypto_from_eddsa_private(shr, key);
    crypto_sign_public_key(pub, key);
    crypto_from_eddsa_public(shr, pub);
}

void hidden(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(hdn, 32);
    crypto_x25519_public_key(pub, key);
    crypto_curve_to_hidden(hdn, pub, 77);
    crypto_hidden_to_curve(pub, hdn);
    crypto_hidden_key_pair(hdn, key, pub);
}

void hidden2(void) {
	uint8_t r[32];
	uint8_t pkf[32] = {
		0x4e,0x25,0xe1,0x7f,0x4c,0xaf,0x3e,0x96,0x81,0x7a,0x74,
		0x41,0xcf,0x6b,0xf9,0x20,0x4a,0xfb,0x5b,0x2c,0x32,0x69,
		0x3f,0xf3,0x16,0xfe,0x54,0x5d,0xd4,0xe3,0x36,0x6f };
	crypto_curve_to_hidden(r, pkf, 161);
}

void hchacha(void) {
    ARRAY(out, 4096);
    ARRAY(key, 32);
    ARRAY(in,  16);
    crypto_hchacha20(out, key, in);
}

void chacha(void) {
    ARRAY(out,   4096);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
     for(size_t i = 0; i < 111; i++)
         crypto_chacha20_ctr(out, 0, i, key, nonce, -4343444);
    //crypto_chacha20_ctr(out, 0, 1024, key, nonce, -123456789);
    // crypto_chacha20(out, 0, 4096, key, key);
}

void xchacha(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    for(size_t i = 0; i < 64; i++)
        crypto_xchacha20(out, 0, i, key, nonce);
}

void ietf_chacha(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 12);
    for(size_t i = 0; i < 64; i++)
        crypto_ietf_chacha20(out, 0, i, key, nonce);

}

void chacha_ctr(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
    for(size_t i = 0; i < 64; i++)
        crypto_chacha20_ctr(out, 0, i, key, nonce, 777);
}

void xchacha_ctr(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    for(size_t i = 0; i < 64; i++)
        crypto_xchacha20_ctr(out, 0, i, key, nonce, 777);
}

void ietf_chacha_ctr(void) {
    ARRAY(out,   64);
    ARRAY(in,    64);
    ARRAY(key,   32);
    ARRAY(nonce, 12);
    for(size_t i = 0; i < 64; i++)
        crypto_ietf_chacha20_ctr(out, 0, i, key, nonce, 777);
}

void x25519(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(shr, 32);
    key[0] = 0;
    crypto_x25519_public_key(pub, key);
    crypto_x25519(shr, key, pub);
}

void dirty(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    crypto_x25519_dirty_small(pub, key);
    crypto_x25519_dirty_fast (pub, key);
}

void inverse(void) {
    ARRAY(key, 32);
    ARRAY(pub, 32);
    ARRAY(bld, 32);
    crypto_x25519_public_key(pub, key);
    crypto_x25519_inverse(bld, key, pub);
}

void sha512(void) {
    ARRAY(hash,  64);
    ARRAY(in  , 128);
    for(size_t i = 0; i < 128; i++)
        crypto_sha512(hash, in, i);
}

void hmac(void) {
    ARRAY(hash, 64);
    ARRAY(key , 128);
    ARRAY(in  , 128);
    for(size_t i = 0; i < 128; i += 8)
    	for(size_t k = 0; k < 128; k += 8)
	        crypto_hmac_sha512(hash, key, k, in, i);
}

void sign_check_ed25519(void) {
    ARRAY(hash, 64);
    ARRAY(key,  32);
    ARRAY(pub,  32);
    ARRAY(in,   32);
    crypto_ed25519_public_key(pub, key);
    crypto_ed25519_sign(hash, key, 0, in, 32);
    crypto_ed25519_check(hash, pub, in, 32);
}

int main(void) {
    p1305();
    blake2b();
    verify();
    wipe();
    lock_unlock();
    argon();
    key_exchange();
    sign_check();
    from_eddsa();
    hidden();
    hidden2();
    hchacha();
    chacha();
    xchacha();
    ietf_chacha();
    chacha_ctr();
    xchacha_ctr();
    ietf_chacha_ctr();
    x25519();
    dirty();
    inverse();
    sha512();
    hmac();
    sign_check_ed25519();
    return 0;
}
