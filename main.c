#include <stdlib.h>
#include <stdio.h>
#include "monocypher.h"
#include "monocypher-ed25519.h"

typedef uint8_t u8;

#define ARRAY(name, size) \
    u8 name[size]; \
    for(size_t i = 0; i < size; i++) name[i] = 123;

void p1305(void) {
    ARRAY(mac, 16);
    ARRAY(key, 32);
    ARRAY(in,  64);
    crypto_poly1305(mac, in,  0, key);
    crypto_poly1305(mac, in, 64, key);
}

void blake2b(void) {
    ARRAY(hash, 64);
    ARRAY(key,  64);
    ARRAY(in,  129);
    crypto_blake2b_general(hash, 64, key, 64, in,   0);
    crypto_blake2b_general(hash, 64, key, 64, in, 129);
}

void verify(void) {
    ARRAY(a, 65);
    ARRAY(b, 65);
    crypto_verify16(a, b);
    crypto_verify32(a, b);
    crypto_verify64(a, b);
}

void wipe(void) {
    ARRAY(a, 123);
    crypto_wipe(a,   0);
    crypto_wipe(a, 123);
}

void lock_unlock(void) {
    ARRAY(mac,   16);
    ARRAY(enc,   64);
    ARRAY(txt,   64);
    ARRAY(key,   33);
    ARRAY(nonce, 25);
    crypto_lock  (mac, enc, key, nonce, txt, 0);
    crypto_unlock(txt, key, nonce, mac, enc, 0);

    crypto_lock  (mac, enc, key, nonce, txt, 64);
    crypto_unlock(txt, key, nonce, mac, enc, 64);
}

void argon(void) {
    ARRAY(hash, 16);
    ARRAY(wrk,  8192); // 8 * 1024
    ARRAY(pwd,  16);
    ARRAY(key,  16);
    ARRAY(slt,  16);
    ARRAY(ad,   16);
    crypto_argon2i_general(hash, 16, wrk, 8, 3, pwd, 16, slt, 16, key, 16, ad, 16);
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
    crypto_sign(hash, key, pub, in, 32);
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

void hchacha(void) {
    ARRAY(out, 32);
    ARRAY(key, 32);
    ARRAY(in,  16);
    crypto_hchacha20(out, key, in);
}

void chacha(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
    crypto_chacha20(out, in,  0, key, nonce);
    crypto_chacha20(out, in, 32, key, nonce);
}

void xchacha(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    crypto_xchacha20(out, in,  0, key, nonce);
    crypto_xchacha20(out, in, 32, key, nonce);
}

void ietf_chacha(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 12);
    crypto_ietf_chacha20(out, in,  0, key, nonce);
    crypto_ietf_chacha20(out, in, 32, key, nonce);
}

void chacha_ctr(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 8);
    crypto_chacha20_ctr(out, in,  0, key, nonce, 777);
    crypto_chacha20_ctr(out, in, 32, key, nonce, 777);
}

void xchacha_ctr(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 24);
    crypto_xchacha20_ctr(out, in,  0, key, nonce, 777);
    crypto_xchacha20_ctr(out, in, 32, key, nonce, 777);
}

void ietf_chacha_ctr(void) {
    ARRAY(out,   32);
    ARRAY(in,    32);
    ARRAY(key,   32);
    ARRAY(nonce, 12);
    crypto_ietf_chacha20_ctr(out, in,  0, key, nonce, 777);
    crypto_ietf_chacha20_ctr(out, in, 32, key, nonce, 777);
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
    crypto_sha512(hash, in,   0);
    crypto_sha512(hash, in, 128);
}

void hmac(void) {
    ARRAY(hash, 64);
    ARRAY(key , 64);
    ARRAY(in  , 64);
    crypto_hmac_sha512(hash, key, 64, in,  0);
    crypto_hmac_sha512(hash, key, 64, in, 64);
}

void sign_check_ed25519(void) {
    ARRAY(hash, 64);
    ARRAY(key,  32);
    ARRAY(pub,  32);
    ARRAY(in,   32);
    crypto_ed25519_public_key(pub, key);
    crypto_ed25519_sign(hash, key, pub, in, 32);
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
