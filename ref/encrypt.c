//
// Created by Hasan, Munawar (IntlAssoc) on 4/19/24.
// Contact: Munawar Hasan - munawar3008@gmail.com
//

/*
    Paper Title: Lynx: Family of Lightweight Authenticated Encryption Schemes Based on Tweakable Blockcipher
    Paper Link: https://ieeexplore.ieee.org/abstract/document/10365684
*/

#include "stdio.h"

#include "skinny.h"
#include "api.h"

#define CTR_BIT_LENGTH 120
#define CTR_BYTES_LENGTH (CTR_BIT_LENGTH / 8)
#define INPUT_SIZE 16
#define TWEAKEY_SIZE 48

void display(const unsigned char *data, unsigned long long l){
    for (unsigned long long i = 0; i < l; ++i) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// increment counter
void inc(unsigned char *counter, int l){
    for (int i = l - 1; i >= 0; i--) {
        if (counter[i] == 0xFF) {
            counter[i] = 0x00;
        } else{
            counter[i]++;
            break;
        }
    }
}

//padding
void pad(unsigned char *state, const unsigned  char **p, unsigned long  long l){
    for (int i = 0; i < l; ++i){
        state[i] = **p;
        (*p)++;
    }
    state[l] = 0x80;
    for (unsigned long long i = l+1; i < 16; ++i)
        state[i] = 0x00;
}

//create tweakey
int make_tweakey(unsigned char *tkey, const unsigned char *tk1, const unsigned char *tk2, const unsigned char *tk3){
    for (int i = 0; i < 16; i++){
        tkey[i] = tk1[i];
        tkey[i + 16] = tk2[i];
        tkey[i + 32] = tk3[i];
    }
    return 0;
}

int crypto_aead_encrypt(
        unsigned char* c, unsigned long long* clen,
        const unsigned char* m, unsigned long long mlen,
        const unsigned char* ad, unsigned long long adlen,
        const unsigned char* nsec,
        const unsigned char* npub,
        const unsigned char* k
        ){

    unsigned char S[INPUT_SIZE] = {0x00}; //stamp
    unsigned char zero_state[INPUT_SIZE] = {0x00}; //zero state
    unsigned char counter[CTR_BYTES_LENGTH] = {0x00}; // 120 bit counter (15 bytes)
    unsigned char h[INPUT_SIZE] = {0x00}; // subsequent outputs of F
    unsigned char tkey[TWEAKEY_SIZE] = {0x00}; // tweakey for storing skinny 128-384 enc and dec
    unsigned char tstate[INPUT_SIZE] = {0x00}; // second part of tweakey
    unsigned char flag = 0x00; // flag value for initialization

    // initialization
    for (int i = 0; i < 16; ++i)
        h[i] = npub[i];
    for (int i = 0; i < 15; ++i)
        S[i] = counter[i];
    S[15] = flag;

    make_tweakey(tkey, S, zero_state, k);
    skinny_128_384_enc(h, tkey);

    // process associated data
    while (adlen > 0){
        if (adlen < 16){
            // padding
            flag = 0x02;
            pad(tstate, &ad, adlen);
            adlen =0;

            for (int i = 0; i < 16; ++i)
                h[i] = h[i] ^ tstate[i];
        }else{
            // no padding
            for (int i = 0; i < 16; ++i) {
                h[i] = h[i] ^ ad[i];
                tstate[i] = ad[i];
            }
            ad = ad + 16;
            adlen -= 16;
            flag = 0x01;
        }

        inc(counter, CTR_BYTES_LENGTH);

        for (int i = 0; i < 15; ++i)
            S[i] = counter[i];
        S[15] = flag;

        make_tweakey(tkey, S, tstate, k);
        skinny_128_384_enc(h, tkey);
    }

    // process message
    *clen = 0;
    while (mlen > 0){
        if (mlen < 16){
            // padding
            flag = 0x04;
            pad(tstate, &m, mlen);

            for (int i = 0; i < 16; ++i)
                h[i] = h[i] ^ tstate[i];

            // copy to ciphertext
            for (int i = 0; i < mlen; ++i){
                c[*clen] = h[i];
                *clen +=1;
            }
            mlen = 0;

        } else{
            //no padding
            flag = 0x03;
            for (int i = 0; i < 16; ++i){
                h[i] = h[i] ^ m[i];

                c[*clen] = h[i];
                *clen += 1;

                tstate[i] = m[i];
            }
            m = m + 16;
            mlen -= 16;
        }

        inc(counter, CTR_BYTES_LENGTH);
        for (int i = 0; i < 15; ++i)
            S[i] = counter[i];
        S[15] = flag;

        make_tweakey(tkey, S, tstate, k);
        skinny_128_384_enc(h, tkey);

    }

    // termination
    flag = 0xff;

    inc(counter, CTR_BYTES_LENGTH);
    for (int i = 0; i < 15; ++i)
        S[i] = counter[i];
    S[15] = flag;

    make_tweakey(tkey, S, zero_state, k);
    skinny_128_384_enc(h, tkey);

    for (int i = 0; i < CRYPTO_ABYTES; ++i){
        c[*clen] = h[i];
        *clen += 1;
    }

    return 0;
}

int crypto_aead_decrypt(
        unsigned char *m,unsigned long long *mlen,
        unsigned char *nsec,
        const unsigned char *c,unsigned long long clen,
        const unsigned char *ad,unsigned long long adlen,
        const unsigned char *npub,
        const unsigned char *k
){
    unsigned char S[INPUT_SIZE] = {0x00}; //stamp
    unsigned char zero_state[INPUT_SIZE] = {0x00}; //zero state
    unsigned char counter[CTR_BYTES_LENGTH] = {0x00}; // 120 bit counter (15 bytes)
    unsigned char h[INPUT_SIZE] = {0x00}; // subsequent outputs of F
    unsigned char tkey[TWEAKEY_SIZE] = {0x00}; // tweakey for storing skinny 128-384 enc and dec
    unsigned char tstate[INPUT_SIZE] = {0x00}; // second part of tweakey
    unsigned char flag = 0x00; // flag value for initialization

    // initialization
    for (int i = 0; i < 16; ++i)
        h[i] = npub[i];
    for (int i = 0; i < 15; ++i)
        S[i] = counter[i];
    S[15] = flag;

    make_tweakey(tkey, S, zero_state, k);
    skinny_128_384_enc(h, tkey);

    // process associated data
    while (adlen > 0){
        if (adlen < 16){
            // padding
            flag = 0x02;
            pad(tstate, &ad, adlen);
            adlen = 0;

            for (int i = 0; i < 16; ++i)
                h[i] = h[i] ^ tstate[i];

        }else{
            // no padding
            for (int i = 0; i < 16; ++i) {
                h[i] = h[i] ^ ad[i];
                tstate[i] = ad[i];
            }
            ad = ad + 16;
            adlen -= 16;
            flag = 0x01;
        }

        inc(counter, CTR_BYTES_LENGTH);

        for (int i = 0; i < 15; ++i)
            S[i] = counter[i];
        S[15] = flag;

        make_tweakey(tkey, S, tstate, k);
        skinny_128_384_enc(h, tkey);
    }

    // process ciphertext
    *mlen = 0;
    clen = clen - 16; // tag
    while (clen > 0){
        if (clen < 16){
            // padding
            flag = 0x04;

            pad(tstate, &c, clen);

            for (int i = 0; i < clen; ++i){
                m[*mlen] = h[i] ^ tstate[i];
                *mlen += 1;
            }

            for (int i = 0; i < clen; ++i){
                h[i] = tstate[i];
            }

            for (int i = 0; i < clen; ++i){
                tstate[i] = m[*mlen - clen + i];
            }

            h[clen] = h[clen] ^ 0x80;

            clen = 0;

        }else{
            //no padding
            flag = 0x03;
            for (int i = 0; i < 16; ++i){
                m[*mlen] = h[i] ^ c[i];
                tstate[i] = m[*mlen];

                *mlen += 1;

                h[i] = c[i];
            }
            c = c + 16;
            clen -= 16;
        }

        inc(counter, CTR_BYTES_LENGTH);

        for (int i = 0; i < 15; ++i)
            S[i] = counter[i];
        S[15] = flag;

        make_tweakey(tkey, S, tstate, k);
        skinny_128_384_enc(h, tkey);

    }

    // termination
    flag = 0xff;
    inc(counter, CTR_BYTES_LENGTH);
    for (int i = 0; i < 15; ++i)
        S[i] = counter[i];
    S[15] = flag;

    make_tweakey(tkey, S, zero_state, k);
    skinny_128_384_enc(h, tkey);

    for (int i = 0; i < CRYPTO_ABYTES; ++i){
        if (c[clen + i] != h[i])
            return -1;
    }

    return 0;
}