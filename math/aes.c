/*
 * aes.c
 *
 * Lightweight MACsec stack
 * Minimal AES implementation for the embedded MACsec stack
 *
 * Copyright (c) 2026 Michal Sarnovsky
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is part of the lightweight MACsec stack.
 * See LICENSE file in the project root for full license text.
 */
#include "aes.h"

static void math_zeroize(void *v, size_t n)
{
    volatile unsigned char *p = (volatile unsigned char *) v;

    while (n-- != 0u)
    {
        *p++ = 0;
    }
}

#define AES_U32(B0, B1, B2, B3)                                                                    \
    (((uint32_t) (B0)) | ((uint32_t) (B1) << 8) | ((uint32_t) (B2) << 16) | ((uint32_t) (B3) << 24))

#define AES_INV_MIXCOL_WORD(X)                                                                     \
    AES_U32(MUL(0x0E, (X)), MUL(0x09, (X)), MUL(0x0D, (X)), MUL(0x0B, (X)))

#define AES_BYTE0(x) ((uint8_t) ((x)))
#define AES_BYTE1(x) ((uint8_t) ((x) >> 8))
#define AES_BYTE2(x) ((uint8_t) ((x) >> 16))
#define AES_BYTE3(x) ((uint8_t) ((x) >> 24))

#define AES_ROTL8(x) (((uint32_t) (x) << 8) | ((uint32_t) (x) >> 24))
#define AES_ROTL16(x) (((uint32_t) (x) << 16) | ((uint32_t) (x) >> 16))
#define AES_ROTL24(x) (((uint32_t) (x) << 24) | ((uint32_t) (x) >> 8))

#define AES_U32_LE(b0, b1, b2, b3)                                                                 \
    (((uint32_t) (uint8_t) (b0)) | ((uint32_t) (uint8_t) (b1) << 8) |                              \
     ((uint32_t) (uint8_t) (b2) << 16) | ((uint32_t) (uint8_t) (b3) << 24))

#define AES_GET_LE32(p, index)                                                                     \
    AES_U32_LE((p)[(index) + 0u], (p)[(index) + 1u], (p)[(index) + 2u], (p)[(index) + 3u])

#define AES_PUT_LE32(p, v, index)                                                                  \
    do                                                                                             \
    {                                                                                              \
        (p)[(index) + 0u] = AES_BYTE0(v);                                                          \
        (p)[(index) + 1u] = AES_BYTE1(v);                                                          \
        (p)[(index) + 2u] = AES_BYTE2(v);                                                          \
        (p)[(index) + 3u] = AES_BYTE3(v);                                                          \
    } while (0)

#define AES_SUBWORD(x)                                                                             \
    AES_U32_LE(FORWARD_S_BOX[AES_BYTE0(x)], FORWARD_S_BOX[AES_BYTE1(x)],                           \
               FORWARD_S_BOX[AES_BYTE2(x)], FORWARD_S_BOX[AES_BYTE3(x)])

#define AES_SUBWORD_ROT(x)                                                                         \
    AES_U32_LE(FORWARD_S_BOX[AES_BYTE1(x)], FORWARD_S_BOX[AES_BYTE2(x)],                           \
               FORWARD_S_BOX[AES_BYTE3(x)], FORWARD_S_BOX[AES_BYTE0(x)])

#define AES_INV_MIX_KEY(x)                                                                         \
    (AES_REVERSE_TABLE_0(FORWARD_S_BOX[AES_BYTE0(x)]) ^                                            \
     AES_REVERSE_TABLE_1(FORWARD_S_BOX[AES_BYTE1(x)]) ^                                            \
     AES_REVERSE_TABLE_2(FORWARD_S_BOX[AES_BYTE2(x)]) ^                                            \
     AES_REVERSE_TABLE_3(FORWARD_S_BOX[AES_BYTE3(x)]))

#if defined(MATH_AES_ROM_TABLES)
/*
 * Forward S-box
 */
static const unsigned char FORWARD_S_BOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

/*
 * Forward tables
 */
#define FORWARD_TABLES                                                                             \
    W32(A5, 63, 63, C6), W32(84, 7C, 7C, F8), W32(99, 77, 77, EE), W32(8D, 7B, 7B, F6),            \
        W32(0D, F2, F2, FF), W32(BD, 6B, 6B, D6), W32(B1, 6F, 6F, DE), W32(54, C5, C5, 91),        \
        W32(50, 30, 30, 60), W32(03, 01, 01, 02), W32(A9, 67, 67, CE), W32(7D, 2B, 2B, 56),        \
        W32(19, FE, FE, E7), W32(62, D7, D7, B5), W32(E6, AB, AB, 4D), W32(9A, 76, 76, EC),        \
        W32(45, CA, CA, 8F), W32(9D, 82, 82, 1F), W32(40, C9, C9, 89), W32(87, 7D, 7D, FA),        \
        W32(15, FA, FA, EF), W32(EB, 59, 59, B2), W32(C9, 47, 47, 8E), W32(0B, F0, F0, FB),        \
        W32(EC, AD, AD, 41), W32(67, D4, D4, B3), W32(FD, A2, A2, 5F), W32(EA, AF, AF, 45),        \
        W32(BF, 9C, 9C, 23), W32(F7, A4, A4, 53), W32(96, 72, 72, E4), W32(5B, C0, C0, 9B),        \
        W32(C2, B7, B7, 75), W32(1C, FD, FD, E1), W32(AE, 93, 93, 3D), W32(6A, 26, 26, 4C),        \
        W32(5A, 36, 36, 6C), W32(41, 3F, 3F, 7E), W32(02, F7, F7, F5), W32(4F, CC, CC, 83),        \
        W32(5C, 34, 34, 68), W32(F4, A5, A5, 51), W32(34, E5, E5, D1), W32(08, F1, F1, F9),        \
        W32(93, 71, 71, E2), W32(73, D8, D8, AB), W32(53, 31, 31, 62), W32(3F, 15, 15, 2A),        \
        W32(0C, 04, 04, 08), W32(52, C7, C7, 95), W32(65, 23, 23, 46), W32(5E, C3, C3, 9D),        \
        W32(28, 18, 18, 30), W32(A1, 96, 96, 37), W32(0F, 05, 05, 0A), W32(B5, 9A, 9A, 2F),        \
        W32(09, 07, 07, 0E), W32(36, 12, 12, 24), W32(9B, 80, 80, 1B), W32(3D, E2, E2, DF),        \
        W32(26, EB, EB, CD), W32(69, 27, 27, 4E), W32(CD, B2, B2, 7F), W32(9F, 75, 75, EA),        \
        W32(1B, 09, 09, 12), W32(9E, 83, 83, 1D), W32(74, 2C, 2C, 58), W32(2E, 1A, 1A, 34),        \
        W32(2D, 1B, 1B, 36), W32(B2, 6E, 6E, DC), W32(EE, 5A, 5A, B4), W32(FB, A0, A0, 5B),        \
        W32(F6, 52, 52, A4), W32(4D, 3B, 3B, 76), W32(61, D6, D6, B7), W32(CE, B3, B3, 7D),        \
        W32(7B, 29, 29, 52), W32(3E, E3, E3, DD), W32(71, 2F, 2F, 5E), W32(97, 84, 84, 13),        \
        W32(F5, 53, 53, A6), W32(68, D1, D1, B9), W32(00, 00, 00, 00), W32(2C, ED, ED, C1),        \
        W32(60, 20, 20, 40), W32(1F, FC, FC, E3), W32(C8, B1, B1, 79), W32(ED, 5B, 5B, B6),        \
        W32(BE, 6A, 6A, D4), W32(46, CB, CB, 8D), W32(D9, BE, BE, 67), W32(4B, 39, 39, 72),        \
        W32(DE, 4A, 4A, 94), W32(D4, 4C, 4C, 98), W32(E8, 58, 58, B0), W32(4A, CF, CF, 85),        \
        W32(6B, D0, D0, BB), W32(2A, EF, EF, C5), W32(E5, AA, AA, 4F), W32(16, FB, FB, ED),        \
        W32(C5, 43, 43, 86), W32(D7, 4D, 4D, 9A), W32(55, 33, 33, 66), W32(94, 85, 85, 11),        \
        W32(CF, 45, 45, 8A), W32(10, F9, F9, E9), W32(06, 02, 02, 04), W32(81, 7F, 7F, FE),        \
        W32(F0, 50, 50, A0), W32(44, 3C, 3C, 78), W32(BA, 9F, 9F, 25), W32(E3, A8, A8, 4B),        \
        W32(F3, 51, 51, A2), W32(FE, A3, A3, 5D), W32(C0, 40, 40, 80), W32(8A, 8F, 8F, 05),        \
        W32(AD, 92, 92, 3F), W32(BC, 9D, 9D, 21), W32(48, 38, 38, 70), W32(04, F5, F5, F1),        \
        W32(DF, BC, BC, 63), W32(C1, B6, B6, 77), W32(75, DA, DA, AF), W32(63, 21, 21, 42),        \
        W32(30, 10, 10, 20), W32(1A, FF, FF, E5), W32(0E, F3, F3, FD), W32(6D, D2, D2, BF),        \
        W32(4C, CD, CD, 81), W32(14, 0C, 0C, 18), W32(35, 13, 13, 26), W32(2F, EC, EC, C3),        \
        W32(E1, 5F, 5F, BE), W32(A2, 97, 97, 35), W32(CC, 44, 44, 88), W32(39, 17, 17, 2E),        \
        W32(57, C4, C4, 93), W32(F2, A7, A7, 55), W32(82, 7E, 7E, FC), W32(47, 3D, 3D, 7A),        \
        W32(AC, 64, 64, C8), W32(E7, 5D, 5D, BA), W32(2B, 19, 19, 32), W32(95, 73, 73, E6),        \
        W32(A0, 60, 60, C0), W32(98, 81, 81, 19), W32(D1, 4F, 4F, 9E), W32(7F, DC, DC, A3),        \
        W32(66, 22, 22, 44), W32(7E, 2A, 2A, 54), W32(AB, 90, 90, 3B), W32(83, 88, 88, 0B),        \
        W32(CA, 46, 46, 8C), W32(29, EE, EE, C7), W32(D3, B8, B8, 6B), W32(3C, 14, 14, 28),        \
        W32(79, DE, DE, A7), W32(E2, 5E, 5E, BC), W32(1D, 0B, 0B, 16), W32(76, DB, DB, AD),        \
        W32(3B, E0, E0, DB), W32(56, 32, 32, 64), W32(4E, 3A, 3A, 74), W32(1E, 0A, 0A, 14),        \
        W32(DB, 49, 49, 92), W32(0A, 06, 06, 0C), W32(6C, 24, 24, 48), W32(E4, 5C, 5C, B8),        \
        W32(5D, C2, C2, 9F), W32(6E, D3, D3, BD), W32(EF, AC, AC, 43), W32(A6, 62, 62, C4),        \
        W32(A8, 91, 91, 39), W32(A4, 95, 95, 31), W32(37, E4, E4, D3), W32(8B, 79, 79, F2),        \
        W32(32, E7, E7, D5), W32(43, C8, C8, 8B), W32(59, 37, 37, 6E), W32(B7, 6D, 6D, DA),        \
        W32(8C, 8D, 8D, 01), W32(64, D5, D5, B1), W32(D2, 4E, 4E, 9C), W32(E0, A9, A9, 49),        \
        W32(B4, 6C, 6C, D8), W32(FA, 56, 56, AC), W32(07, F4, F4, F3), W32(25, EA, EA, CF),        \
        W32(AF, 65, 65, CA), W32(8E, 7A, 7A, F4), W32(E9, AE, AE, 47), W32(18, 08, 08, 10),        \
        W32(D5, BA, BA, 6F), W32(88, 78, 78, F0), W32(6F, 25, 25, 4A), W32(72, 2E, 2E, 5C),        \
        W32(24, 1C, 1C, 38), W32(F1, A6, A6, 57), W32(C7, B4, B4, 73), W32(51, C6, C6, 97),        \
        W32(23, E8, E8, CB), W32(7C, DD, DD, A1), W32(9C, 74, 74, E8), W32(21, 1F, 1F, 3E),        \
        W32(DD, 4B, 4B, 96), W32(DC, BD, BD, 61), W32(86, 8B, 8B, 0D), W32(85, 8A, 8A, 0F),        \
        W32(90, 70, 70, E0), W32(42, 3E, 3E, 7C), W32(C4, B5, B5, 71), W32(AA, 66, 66, CC),        \
        W32(D8, 48, 48, 90), W32(05, 03, 03, 06), W32(01, F6, F6, F7), W32(12, 0E, 0E, 1C),        \
        W32(A3, 61, 61, C2), W32(5F, 35, 35, 6A), W32(F9, 57, 57, AE), W32(D0, B9, B9, 69),        \
        W32(91, 86, 86, 17), W32(58, C1, C1, 99), W32(27, 1D, 1D, 3A), W32(B9, 9E, 9E, 27),        \
        W32(38, E1, E1, D9), W32(13, F8, F8, EB), W32(B3, 98, 98, 2B), W32(33, 11, 11, 22),        \
        W32(BB, 69, 69, D2), W32(70, D9, D9, A9), W32(89, 8E, 8E, 07), W32(A7, 94, 94, 33),        \
        W32(B6, 9B, 9B, 2D), W32(22, 1E, 1E, 3C), W32(92, 87, 87, 15), W32(20, E9, E9, C9),        \
        W32(49, CE, CE, 87), W32(FF, 55, 55, AA), W32(78, 28, 28, 50), W32(7A, DF, DF, A5),        \
        W32(8F, 8C, 8C, 03), W32(F8, A1, A1, 59), W32(80, 89, 89, 09), W32(17, 0D, 0D, 1A),        \
        W32(DA, BF, BF, 65), W32(31, E6, E6, D7), W32(C6, 42, 42, 84), W32(B8, 68, 68, D0),        \
        W32(C3, 41, 41, 82), W32(B0, 99, 99, 29), W32(77, 2D, 2D, 5A), W32(11, 0F, 0F, 1E),        \
        W32(CB, B0, B0, 7B), W32(FC, 54, 54, A8), W32(D6, BB, BB, 6D), W32(3A, 16, 16, 2C)

#define AES_U32_BE(B0, B1, B2, B3)                                                                 \
    (((uint32_t) 0x##B0 << 24) | ((uint32_t) 0x##B1 << 16) | ((uint32_t) 0x##B2 << 8) |            \
     ((uint32_t) 0x##B3))

#define AES_TABLE_WORD(A, B, C, D) AES_U32_BE(A, B, C, D)

#define W32(a, b, c, d) AES_TABLE_WORD(a, b, c, d)
static const uint32_t FORWARD_TABLES_0[256] = {FORWARD_TABLES};
#undef W32

#if !defined(MATH_AES_FEWER_TABLES)
#define W32(a, b, c, d) AES_TABLE_WORD(b, c, d, a)
static const uint32_t FORWARD_TABLES_1[256] = {FORWARD_TABLES};
#undef W32

#define W32(a, b, c, d) AES_TABLE_WORD(c, d, a, b)
static const uint32_t FORWARD_TABLES_2[256] = {FORWARD_TABLES};
#undef W32

#define W32(a, b, c, d) AES_TABLE_WORD(d, a, b, c)
static const uint32_t FORWARD_TABLES_3[256] = {FORWARD_TABLES};
#undef W32
#endif /* !MATH_AES_FEWER_TABLES */

/*
 * Reverse S-box
 */
static const unsigned char REVERSE_S_BOX[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

/*
 * Reverse tables
 */
#define REVERSE_TABLES                                                                             \
    W32(50, A7, F4, 51), W32(53, 65, 41, 7E), W32(C3, A4, 17, 1A), W32(96, 5E, 27, 3A),            \
        W32(CB, 6B, AB, 3B), W32(F1, 45, 9D, 1F), W32(AB, 58, FA, AC), W32(93, 03, E3, 4B),        \
        W32(55, FA, 30, 20), W32(F6, 6D, 76, AD), W32(91, 76, CC, 88), W32(25, 4C, 02, F5),        \
        W32(FC, D7, E5, 4F), W32(D7, CB, 2A, C5), W32(80, 44, 35, 26), W32(8F, A3, 62, B5),        \
        W32(49, 5A, B1, DE), W32(67, 1B, BA, 25), W32(98, 0E, EA, 45), W32(E1, C0, FE, 5D),        \
        W32(02, 75, 2F, C3), W32(12, F0, 4C, 81), W32(A3, 97, 46, 8D), W32(C6, F9, D3, 6B),        \
        W32(E7, 5F, 8F, 03), W32(95, 9C, 92, 15), W32(EB, 7A, 6D, BF), W32(DA, 59, 52, 95),        \
        W32(2D, 83, BE, D4), W32(D3, 21, 74, 58), W32(29, 69, E0, 49), W32(44, C8, C9, 8E),        \
        W32(6A, 89, C2, 75), W32(78, 79, 8E, F4), W32(6B, 3E, 58, 99), W32(DD, 71, B9, 27),        \
        W32(B6, 4F, E1, BE), W32(17, AD, 88, F0), W32(66, AC, 20, C9), W32(B4, 3A, CE, 7D),        \
        W32(18, 4A, DF, 63), W32(82, 31, 1A, E5), W32(60, 33, 51, 97), W32(45, 7F, 53, 62),        \
        W32(E0, 77, 64, B1), W32(84, AE, 6B, BB), W32(1C, A0, 81, FE), W32(94, 2B, 08, F9),        \
        W32(58, 68, 48, 70), W32(19, FD, 45, 8F), W32(87, 6C, DE, 94), W32(B7, F8, 7B, 52),        \
        W32(23, D3, 73, AB), W32(E2, 02, 4B, 72), W32(57, 8F, 1F, E3), W32(2A, AB, 55, 66),        \
        W32(07, 28, EB, B2), W32(03, C2, B5, 2F), W32(9A, 7B, C5, 86), W32(A5, 08, 37, D3),        \
        W32(F2, 87, 28, 30), W32(B2, A5, BF, 23), W32(BA, 6A, 03, 02), W32(5C, 82, 16, ED),        \
        W32(2B, 1C, CF, 8A), W32(92, B4, 79, A7), W32(F0, F2, 07, F3), W32(A1, E2, 69, 4E),        \
        W32(CD, F4, DA, 65), W32(D5, BE, 05, 06), W32(1F, 62, 34, D1), W32(8A, FE, A6, C4),        \
        W32(9D, 53, 2E, 34), W32(A0, 55, F3, A2), W32(32, E1, 8A, 05), W32(75, EB, F6, A4),        \
        W32(39, EC, 83, 0B), W32(AA, EF, 60, 40), W32(06, 9F, 71, 5E), W32(51, 10, 6E, BD),        \
        W32(F9, 8A, 21, 3E), W32(3D, 06, DD, 96), W32(AE, 05, 3E, DD), W32(46, BD, E6, 4D),        \
        W32(B5, 8D, 54, 91), W32(05, 5D, C4, 71), W32(6F, D4, 06, 04), W32(FF, 15, 50, 60),        \
        W32(24, FB, 98, 19), W32(97, E9, BD, D6), W32(CC, 43, 40, 89), W32(77, 9E, D9, 67),        \
        W32(BD, 42, E8, B0), W32(88, 8B, 89, 07), W32(38, 5B, 19, E7), W32(DB, EE, C8, 79),        \
        W32(47, 0A, 7C, A1), W32(E9, 0F, 42, 7C), W32(C9, 1E, 84, F8), W32(00, 00, 00, 00),        \
        W32(83, 86, 80, 09), W32(48, ED, 2B, 32), W32(AC, 70, 11, 1E), W32(4E, 72, 5A, 6C),        \
        W32(FB, FF, 0E, FD), W32(56, 38, 85, 0F), W32(1E, D5, AE, 3D), W32(27, 39, 2D, 36),        \
        W32(64, D9, 0F, 0A), W32(21, A6, 5C, 68), W32(D1, 54, 5B, 9B), W32(3A, 2E, 36, 24),        \
        W32(B1, 67, 0A, 0C), W32(0F, E7, 57, 93), W32(D2, 96, EE, B4), W32(9E, 91, 9B, 1B),        \
        W32(4F, C5, C0, 80), W32(A2, 20, DC, 61), W32(69, 4B, 77, 5A), W32(16, 1A, 12, 1C),        \
        W32(0A, BA, 93, E2), W32(E5, 2A, A0, C0), W32(43, E0, 22, 3C), W32(1D, 17, 1B, 12),        \
        W32(0B, 0D, 09, 0E), W32(AD, C7, 8B, F2), W32(B9, A8, B6, 2D), W32(C8, A9, 1E, 14),        \
        W32(85, 19, F1, 57), W32(4C, 07, 75, AF), W32(BB, DD, 99, EE), W32(FD, 60, 7F, A3),        \
        W32(9F, 26, 01, F7), W32(BC, F5, 72, 5C), W32(C5, 3B, 66, 44), W32(34, 7E, FB, 5B),        \
        W32(76, 29, 43, 8B), W32(DC, C6, 23, CB), W32(68, FC, ED, B6), W32(63, F1, E4, B8),        \
        W32(CA, DC, 31, D7), W32(10, 85, 63, 42), W32(40, 22, 97, 13), W32(20, 11, C6, 84),        \
        W32(7D, 24, 4A, 85), W32(F8, 3D, BB, D2), W32(11, 32, F9, AE), W32(6D, A1, 29, C7),        \
        W32(4B, 2F, 9E, 1D), W32(F3, 30, B2, DC), W32(EC, 52, 86, 0D), W32(D0, E3, C1, 77),        \
        W32(6C, 16, B3, 2B), W32(99, B9, 70, A9), W32(FA, 48, 94, 11), W32(22, 64, E9, 47),        \
        W32(C4, 8C, FC, A8), W32(1A, 3F, F0, A0), W32(D8, 2C, 7D, 56), W32(EF, 90, 33, 22),        \
        W32(C7, 4E, 49, 87), W32(C1, D1, 38, D9), W32(FE, A2, CA, 8C), W32(36, 0B, D4, 98),        \
        W32(CF, 81, F5, A6), W32(28, DE, 7A, A5), W32(26, 8E, B7, DA), W32(A4, BF, AD, 3F),        \
        W32(E4, 9D, 3A, 2C), W32(0D, 92, 78, 50), W32(9B, CC, 5F, 6A), W32(62, 46, 7E, 54),        \
        W32(C2, 13, 8D, F6), W32(E8, B8, D8, 90), W32(5E, F7, 39, 2E), W32(F5, AF, C3, 82),        \
        W32(BE, 80, 5D, 9F), W32(7C, 93, D0, 69), W32(A9, 2D, D5, 6F), W32(B3, 12, 25, CF),        \
        W32(3B, 99, AC, C8), W32(A7, 7D, 18, 10), W32(6E, 63, 9C, E8), W32(7B, BB, 3B, DB),        \
        W32(09, 78, 26, CD), W32(F4, 18, 59, 6E), W32(01, B7, 9A, EC), W32(A8, 9A, 4F, 83),        \
        W32(65, 6E, 95, E6), W32(7E, E6, FF, AA), W32(08, CF, BC, 21), W32(E6, E8, 15, EF),        \
        W32(D9, 9B, E7, BA), W32(CE, 36, 6F, 4A), W32(D4, 09, 9F, EA), W32(D6, 7C, B0, 29),        \
        W32(AF, B2, A4, 31), W32(31, 23, 3F, 2A), W32(30, 94, A5, C6), W32(C0, 66, A2, 35),        \
        W32(37, BC, 4E, 74), W32(A6, CA, 82, FC), W32(B0, D0, 90, E0), W32(15, D8, A7, 33),        \
        W32(4A, 98, 04, F1), W32(F7, DA, EC, 41), W32(0E, 50, CD, 7F), W32(2F, F6, 91, 17),        \
        W32(8D, D6, 4D, 76), W32(4D, B0, EF, 43), W32(54, 4D, AA, CC), W32(DF, 04, 96, E4),        \
        W32(E3, B5, D1, 9E), W32(1B, 88, 6A, 4C), W32(B8, 1F, 2C, C1), W32(7F, 51, 65, 46),        \
        W32(04, EA, 5E, 9D), W32(5D, 35, 8C, 01), W32(73, 74, 87, FA), W32(2E, 41, 0B, FB),        \
        W32(5A, 1D, 67, B3), W32(52, D2, DB, 92), W32(33, 56, 10, E9), W32(13, 47, D6, 6D),        \
        W32(8C, 61, D7, 9A), W32(7A, 0C, A1, 37), W32(8E, 14, F8, 59), W32(89, 3C, 13, EB),        \
        W32(EE, 27, A9, CE), W32(35, C9, 61, B7), W32(ED, E5, 1C, E1), W32(3C, B1, 47, 7A),        \
        W32(59, DF, D2, 9C), W32(3F, 73, F2, 55), W32(79, CE, 14, 18), W32(BF, 37, C7, 73),        \
        W32(EA, CD, F7, 53), W32(5B, AA, FD, 5F), W32(14, 6F, 3D, DF), W32(86, DB, 44, 78),        \
        W32(81, F3, AF, CA), W32(3E, C4, 68, B9), W32(2C, 34, 24, 38), W32(5F, 40, A3, C2),        \
        W32(72, C3, 1D, 16), W32(0C, 25, E2, BC), W32(8B, 49, 3C, 28), W32(41, 95, 0D, FF),        \
        W32(71, 01, A8, 39), W32(DE, B3, 0C, 08), W32(9C, E4, B4, D8), W32(90, C1, 56, 64),        \
        W32(61, 84, CB, 7B), W32(70, B6, 32, D5), W32(74, 5C, 6C, 48), W32(42, 57, B8, D0)

#define W32(a, b, c, d) 0x##a##b##c##d
static const uint32_t REVERSE_TABLES_0[256] = {REVERSE_TABLES};
#undef W32

#if !defined(MATH_AES_FEWER_TABLES)
#define W32(a, b, c, d) 0x##b##c##d##a
static const uint32_t REVERSE_TABLES_1[256] = {REVERSE_TABLES};
#undef W32

#define W32(a, b, c, d) 0x##c##d##a##b
static const uint32_t REVERSE_TABLES_2[256] = {REVERSE_TABLES};
#undef W32

#define W32(a, b, c, d) 0x##d##a##b##c
static const uint32_t REVERSE_TABLES_3[256] = {REVERSE_TABLES};
#undef W32
#endif /* !MATH_AES_FEWER_TABLES */

#undef REVERSE_TABLES

/*
 * Round constants
 */
static const uint32_t RCON[10] = {0x00000001, 0x00000002, 0x00000004, 0x00000008, 0x00000010,
                                  0x00000020, 0x00000040, 0x00000080, 0x0000001B, 0x00000036};

#else /* MATH_AES_ROM_TABLES */

/*
 * Runtime-generated shared AES lookup tables.
 * Generated once during the first key expansion.
 */
static unsigned char FORWARD_S_BOX[256];
static uint32_t FORWARD_TABLES_0[256];

#if !defined(MATH_AES_FEWER_TABLES)
static uint32_t FORWARD_TABLES_1[256];
static uint32_t FORWARD_TABLES_2[256];
static uint32_t FORWARD_TABLES_3[256];
#endif

/*
 * Runtime-generated shared inverse lookup tables.
 * Generated once during the first key expansion.
 */
static unsigned char REVERSE_S_BOX[256];
static uint32_t REVERSE_TABLES_0[256];

#if !defined(MATH_AES_FEWER_TABLES)
static uint32_t REVERSE_TABLES_1[256];
static uint32_t REVERSE_TABLES_2[256];
static uint32_t REVERSE_TABLES_3[256];
#endif

/*
 * Round constants
 */
static uint32_t RCON[10];

/*
 * Tables generation code
 */
#define XTIME(x) ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00))
#define MUL(x, y) ((x && y) ? ctx->pow[(ctx->log[x] + ctx->log[y]) % 255] : 0)

static macsec_bool_t aes_init_done = MACSEC_FALSE;

static void aes_gen_tables(math_aes_context *ctx)
{
    unsigned int index;
    unsigned int value;
    unsigned int inverse;
    unsigned int rotated;
    unsigned int substituted;
    unsigned int multiplied_by_two;
    unsigned int multiplied_by_three;
    uint32_t table_word;

    /*
     * Build exponent and logarithm tables over GF(2^8).
     */
    index = 0u;
    value = 1u;

    do
    {
        ctx->pow[index] = (int) value;
        ctx->log[value] = (int) index;

        value ^= XTIME(value);
        value &= 0xFFu;

        ++index;
    } while (index < 256u);

    /*
     * Generate AES round constants.
     */
    index = 0u;
    value = 1u;

    while (index < 10u)
    {
        RCON[index] = (uint32_t) value;

        value = XTIME(value) & 0xFFu;
        ++index;
    }

    /*
     * Generate the forward S-box.
     *
     * Zero is the only byte without a multiplicative inverse
     * in GF(2^8), so its substituted value is assigned directly.
     */
    FORWARD_S_BOX[0] = 0x63u;

    for (index = 1u; index < 256u; ++index)
    {
        inverse = (unsigned int) ctx->pow[255 - ctx->log[index]];

        substituted = inverse;
        rotated = inverse;

        /*
         * AES affine transformation:
         *
         * S(x) = x ^ ROTL1(x) ^ ROTL2(x) ^
         *        ROTL3(x) ^ ROTL4(x) ^ 0x63
         */
        value = 0u;

        while (value < 4u)
        {
            rotated = ((rotated << 1) | (rotated >> 7)) & 0xFFu;

            substituted ^= rotated;
            ++value;
        }

        substituted ^= 0x63u;

        FORWARD_S_BOX[index] = (unsigned char) (substituted & 0xFFu);
    }

    /*
     * Construct the reverse S-box from the completed
     * forward S-box.
     */
    index = 0u;

    do
    {
        substituted = FORWARD_S_BOX[index];
        REVERSE_S_BOX[substituted] = (unsigned char) index;

        ++index;
    } while (index < 256u);

    /*
     * Generate the encryption lookup tables.
     */
    index = 0u;

    while (index < 256u)
    {
        substituted = FORWARD_S_BOX[index];

        multiplied_by_two = XTIME(substituted) & 0xFFu;

        multiplied_by_three = multiplied_by_two ^ substituted;

        table_word = AES_U32(multiplied_by_two, substituted, substituted, multiplied_by_three);

        FORWARD_TABLES_0[index] = table_word;

#if !defined(MATH_AES_FEWER_TABLES)
        table_word = AES_ROTL8(table_word);
        FORWARD_TABLES_1[index] = table_word;

        table_word = AES_ROTL8(table_word);
        FORWARD_TABLES_2[index] = table_word;

        table_word = AES_ROTL8(table_word);
        FORWARD_TABLES_3[index] = table_word;
#endif

        ++index;
    }

    /*
     * Generate the decryption lookup tables.
     */
    for (index = 0u; index < 256u; ++index)
    {
        table_word = AES_INV_MIXCOL_WORD(REVERSE_S_BOX[index]);

        REVERSE_TABLES_0[index] = table_word;

#if !defined(MATH_AES_FEWER_TABLES)
        table_word = AES_ROTL8(table_word);
        REVERSE_TABLES_1[index] = table_word;

        table_word = AES_ROTL8(table_word);
        REVERSE_TABLES_2[index] = table_word;

        table_word = AES_ROTL8(table_word);
        REVERSE_TABLES_3[index] = table_word;
#endif
    }
}

#endif /* MATH_AES_ROM_TABLES */

/*
 * With MATH_AES_FEWER_TABLES enabled, only table 0 is stored.
 * Tables 1..3 are obtained by rotating the selected 32-bit table word.
 */
#define AES_FORWARD_TABLE_0(i) (FORWARD_TABLES_0[(i)])
#define AES_REVERSE_TABLE_0(i) (REVERSE_TABLES_0[(i)])

#if defined(MATH_AES_FEWER_TABLES)
#define AES_FORWARD_TABLE_1(i) AES_ROTL8(FORWARD_TABLES_0[(i)])
#define AES_FORWARD_TABLE_2(i) AES_ROTL16(FORWARD_TABLES_0[(i)])
#define AES_FORWARD_TABLE_3(i) AES_ROTL24(FORWARD_TABLES_0[(i)])

#define AES_REVERSE_TABLE_1(i) AES_ROTL8(REVERSE_TABLES_0[(i)])
#define AES_REVERSE_TABLE_2(i) AES_ROTL16(REVERSE_TABLES_0[(i)])
#define AES_REVERSE_TABLE_3(i) AES_ROTL24(REVERSE_TABLES_0[(i)])
#else
#define AES_FORWARD_TABLE_1(i) (FORWARD_TABLES_1[(i)])
#define AES_FORWARD_TABLE_2(i) (FORWARD_TABLES_2[(i)])
#define AES_FORWARD_TABLE_3(i) (FORWARD_TABLES_3[(i)])

#define AES_REVERSE_TABLE_1(i) (REVERSE_TABLES_1[(i)])
#define AES_REVERSE_TABLE_2(i) (REVERSE_TABLES_2[(i)])
#define AES_REVERSE_TABLE_3(i) (REVERSE_TABLES_3[(i)])
#endif

void math_aes_init(math_aes_context *ctx) { memset(ctx, 0, sizeof(math_aes_context)); }

void math_aes_free(math_aes_context *ctx)
{
    macsec_assert(ctx != NULL);

    math_zeroize(ctx, sizeof(math_aes_context));
}

/*
 * AES key schedule (encryption)
 */
int math_aes_setenckey(math_aes_context *ctx, const uint8_t *key, uint32_t keybits)
{
    uint32_t i;
    uint32_t key_words;
    uint32_t total_words;
    uint32_t temp;
    uint32_t *round_keys;

#if !defined(MATH_AES_ROM_TABLES)
    if (aes_init_done != MACSEC_TRUE)
    {
        aes_gen_tables(ctx);
        aes_init_done = MACSEC_TRUE;
    }
#endif

    if (keybits == 128u)
    {
        key_words = 4u;
        ctx->number_of_rounds = 10;
    }
    else if (keybits == 192u)
    {
        key_words = 6u;
        ctx->number_of_rounds = 12;
    }
    else if (keybits == 256u)
    {
        key_words = 8u;
        ctx->number_of_rounds = 14;
    }
    else
    {
        return -1;
    }

    round_keys = ctx->buf;
    ctx->round_keys = round_keys;

    /*
     * Copy the original cipher key into the beginning
     * of the expanded round-key buffer.
     */
    i = 0u;

    while (i < key_words)
    {
        round_keys[i] = AES_GET_LE32(key, i * 4u);
        ++i;
    }

    /*
     * AES requires one 128-bit round key for the initial
     * AddRoundKey operation and one for every round.
     */
    total_words = 4u * ((uint32_t) ctx->number_of_rounds + 1u);

    /*
     * Expand the key word by word.
     */
    while (i < total_words)
    {
        temp = round_keys[i - 1u];

        if ((i % key_words) == 0u)
        {
            temp = AES_SUBWORD_ROT(temp) ^ RCON[(i / key_words) - 1u];
        }
        else if ((key_words == 8u) && ((i % key_words) == 4u))
        {
            temp = AES_SUBWORD(temp);
        }

        round_keys[i] = round_keys[i - key_words] ^ temp;
        ++i;
    }

    return 0;
}

int math_aes_setdeckey(math_aes_context *ctx, const uint8_t *key, uint32_t keybits)
{
    int ret;
    uint32_t round;
    uint32_t word;
    uint32_t source_index;
    uint32_t destination_index;
    math_aes_context encryption_ctx;

    math_aes_init(&encryption_ctx);

    ctx->round_keys = ctx->buf;

    /*
     * Generate the encryption key schedule first.
     * This also validates keybits.
     */
    ret = math_aes_setenckey(&encryption_ctx, key, keybits);

    if (ret == 0)
    {
        ctx->number_of_rounds = encryption_ctx.number_of_rounds;

        /*
         * The first decryption round key is the final
         * encryption round key, without InvMixColumns.
         */
        source_index = (uint32_t) ctx->number_of_rounds * 4u;

        for (word = 0u; word < 4u; ++word)
        {
            ctx->buf[word] = encryption_ctx.round_keys[source_index + word];
        }

        destination_index = 4u;

        /*
         * Copy the intermediate encryption round keys
         * in reverse order and apply InvMixColumns.
         */
        round = (uint32_t) ctx->number_of_rounds - 1u;

        while (round > 0u)
        {
            source_index = round * 4u;

            for (word = 0u; word < 4u; ++word)
            {
                ctx->buf[destination_index + word] =
                    AES_INV_MIX_KEY(encryption_ctx.round_keys[source_index + word]);
            }

            destination_index += 4u;
            --round;
        }

        /*
         * The final decryption round key is the original
         * cipher key, also without InvMixColumns.
         */
        for (word = 0u; word < 4u; ++word)
        {
            ctx->buf[destination_index + word] = encryption_ctx.round_keys[word];
        }
    }

    math_aes_free(&encryption_ctx);

    return ret;
}

#define AES_FORWARD_ROUND_WORD(RK, A, B, C, D)                                                     \
    ((RK) ^ AES_FORWARD_TABLE_0(AES_BYTE0(A)) ^ AES_FORWARD_TABLE_1(AES_BYTE1(B)) ^                \
     AES_FORWARD_TABLE_2(AES_BYTE2(C)) ^ AES_FORWARD_TABLE_3(AES_BYTE3(D)))

#define AES_FORWARD_FINAL_WORD(RK, A, B, C, D)                                                     \
    ((RK) ^ AES_U32_LE(FORWARD_S_BOX[AES_BYTE0(A)], FORWARD_S_BOX[AES_BYTE1(B)],                   \
                       FORWARD_S_BOX[AES_BYTE2(C)], FORWARD_S_BOX[AES_BYTE3(D)]))

int math_aes_encrypt(math_aes_context *ctx, const uint8_t input[16], uint8_t output[16])
{
    uint32_t round;
    uint32_t column;
    uint32_t next1;
    uint32_t next2;
    uint32_t next3;
    uint32_t key_index;
    uint32_t state[4];
    uint32_t transformed[4];
    const uint32_t *round_keys;

    round_keys = ctx->round_keys;

    /*
     * Load the input state and apply the initial AddRoundKey.
     */
    for (column = 0u; column < 4u; ++column)
    {
        state[column] = AES_GET_LE32(input, column * 4u) ^ round_keys[column];
    }

    key_index = 4u;

    /*
     * Process all regular AES rounds.
     */
    round = 1u;

    while (round < (uint32_t) ctx->number_of_rounds)
    {
        for (column = 0u; column < 4u; ++column)
        {
            next1 = (column + 1u) & 3u;
            next2 = (column + 2u) & 3u;
            next3 = (column + 3u) & 3u;

            transformed[column] =
                AES_FORWARD_ROUND_WORD(round_keys[key_index + column], state[column], state[next1],
                                       state[next2], state[next3]);
        }

        for (column = 0u; column < 4u; ++column)
        {
            state[column] = transformed[column];
        }

        key_index += 4u;
        ++round;
    }

    /*
     * The final AES round omits MixColumns.
     */
    for (column = 0u; column < 4u; ++column)
    {
        next1 = (column + 1u) & 3u;
        next2 = (column + 2u) & 3u;
        next3 = (column + 3u) & 3u;

        transformed[column] = AES_FORWARD_FINAL_WORD(round_keys[key_index + column], state[column],
                                                     state[next1], state[next2], state[next3]);
    }

    /*
     * Store the resulting ciphertext.
     */
    for (column = 0u; column < 4u; ++column)
    {
        AES_PUT_LE32(output, transformed[column], column * 4u);
    }

    return 0;
}

#define AES_REVERSE_ROUND_WORD(RK, A, B, C, D)                                                     \
    ((RK) ^ AES_REVERSE_TABLE_0(AES_BYTE0(A)) ^ AES_REVERSE_TABLE_1(AES_BYTE1(B)) ^                \
     AES_REVERSE_TABLE_2(AES_BYTE2(C)) ^ AES_REVERSE_TABLE_3(AES_BYTE3(D)))

#define AES_REVERSE_FINAL_WORD(RK, A, B, C, D)                                                     \
    ((RK) ^ AES_U32_LE(REVERSE_S_BOX[AES_BYTE0(A)], REVERSE_S_BOX[AES_BYTE1(B)],                   \
                       REVERSE_S_BOX[AES_BYTE2(C)], REVERSE_S_BOX[AES_BYTE3(D)]))

int math_aes_decrypt(math_aes_context *ctx, const uint8_t input[16], uint8_t output[16])
{
    uint32_t round;
    uint32_t column;
    uint32_t prev1;
    uint32_t prev2;
    uint32_t prev3;
    uint32_t key_index;
    uint32_t state[4];
    uint32_t transformed[4];
    const uint32_t *round_keys;

    round_keys = ctx->round_keys;

    /*
     * Load the ciphertext state and apply the initial
     * decryption round key.
     */
    for (column = 0u; column < 4u; ++column)
    {
        state[column] = AES_GET_LE32(input, column * 4u) ^ round_keys[column];
    }

    key_index = 4u;

    /*
     * Process all regular inverse AES rounds.
     */
    round = 1u;

    while (round < (uint32_t) ctx->number_of_rounds)
    {
        for (column = 0u; column < 4u; ++column)
        {
            prev1 = (column + 3u) & 3u;
            prev2 = (column + 2u) & 3u;
            prev3 = (column + 1u) & 3u;

            transformed[column] =
                AES_REVERSE_ROUND_WORD(round_keys[key_index + column], state[column], state[prev1],
                                       state[prev2], state[prev3]);
        }

        for (column = 0u; column < 4u; ++column)
        {
            state[column] = transformed[column];
        }

        key_index += 4u;
        ++round;
    }

    /*
     * The final inverse AES round omits InvMixColumns.
     */
    for (column = 0u; column < 4u; ++column)
    {
        prev1 = (column + 3u) & 3u;
        prev2 = (column + 2u) & 3u;
        prev3 = (column + 1u) & 3u;

        transformed[column] = AES_REVERSE_FINAL_WORD(round_keys[key_index + column], state[column],
                                                     state[prev1], state[prev2], state[prev3]);
    }

    /*
     * Store the recovered plaintext.
     */
    for (column = 0u; column < 4u; ++column)
    {
        AES_PUT_LE32(output, transformed[column], column * 4u);
    }

    return 0;
}

#if defined(MATH_SELF_TEST)

static const unsigned char aes_test_ecb_dec[3][16] = {
    {0x9D, 0x1A, 0x35, 0x3C, 0x86, 0x7D, 0x41, 0xFB, 0x5B, 0x55, 0x38, 0x8D, 0x14, 0x9E, 0x84,
     0xFD},
    {0xB7, 0x6A, 0x17, 0x61, 0x47, 0x9E, 0x72, 0x9D, 0xAB, 0x88, 0x2D, 0xDD, 0x91, 0x01, 0x02,
     0x9B},
    {0x9E, 0x69, 0xA6, 0x57, 0xB0, 0x2D, 0x93, 0xD1, 0x20, 0x2F, 0x07, 0xBF, 0xF6, 0x77, 0x8D,
     0xA1}};

static const unsigned char aes_test_ecb_enc[3][16] = {
    {0x47, 0x2B, 0x56, 0xF0, 0xBE, 0x7D, 0x8A, 0xE7, 0x72, 0x33, 0x47, 0x84, 0xE5, 0xCE, 0x29,
     0x3E},
    {0x35, 0x8D, 0xAE, 0x57, 0x83, 0x04, 0xC7, 0x71, 0x30, 0xBD, 0x0A, 0xDA, 0x76, 0x75, 0xD5,
     0xCA},
    {0x70, 0xDF, 0xF6, 0xF5, 0x0C, 0x1D, 0xE1, 0xA9, 0x9F, 0x55, 0xF1, 0x8D, 0xC2, 0x3B, 0xDF,
     0xCF}};

int math_aes_self_test(math_aes_context *ctx, int verbose)
{
    int ret = 0;
    int j;
    int key_size;
    int array_index;
    unsigned char key[32];
    unsigned char buf[16];

    memset(key, 0, sizeof(key));
    math_aes_init(ctx);

    for (key_size = 128, array_index = 0; key_size <= 256; key_size += 64, array_index++)
    {
        if (verbose != 0)
        {
            macsec_printf("  AES-ECB-%3d (dec): ", key_size);
        }

        memcpy(buf, aes_test_ecb_enc[array_index], 16);

        ret = math_aes_setdeckey(ctx, key, key_size);
        if (ret != 0)
        {
            goto exit;
        }

        for (j = 0; j < 10000; j++)
        {
            (void) math_aes_decrypt(ctx, buf, buf);
        }

        if (macsec_compare(buf, aes_test_ecb_dec[array_index], 16) != 0)
        {
            ret = 1;
            goto exit;
        }

        if (verbose != 0)
        {
            macsec_printf("passed\n");
        }

        if (verbose != 0)
        {
            macsec_printf("  AES-ECB-%3d (enc): ", key_size);
        }

        memcpy(buf, aes_test_ecb_dec[array_index], 16);

        ret = math_aes_setenckey(ctx, key, key_size);
        if (ret != 0)
        {
            goto exit;
        }

        for (j = 0; j < 10000; j++)
        {
            (void) math_aes_encrypt(ctx, buf, buf);
        }

        if (macsec_compare(buf, aes_test_ecb_enc[array_index], 16) != 0)
        {
            ret = 1;
            goto exit;
        }

        if (verbose != 0)
        {
            macsec_printf("passed\n");
        }
    }

    if (verbose != 0)
    {
        macsec_printf("\n");
    }

    ret = 0;

exit:
    if (ret != 0 && verbose != 0)
    {
        macsec_printf("failed\n");
    }

    math_aes_free(ctx);
    return (ret);
}

#endif /* MATH_SELF_TEST */
