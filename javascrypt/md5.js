/*
 *  md5.jvs 1.0b 27/06/96
 *
 * Javascript implementation of the RSA Data Security, Inc. MD5
 * Message-Digest Algorithm.
 *
 * Copyright (c) 1996 Henri Torgemane. All Rights Reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purposes and without
 * fee is hereby granted provided that this copyright notice
 * appears in all copies.
 *
 * Of course, this soft is provided "as is" without express or implied
 * warranty of any kind.

    This version contains some trivial reformatting modifications
    by John Walker.

 */


/* NOTE: This has been modified from the original for 'ajbcrypt' by
   prefixing md5_ to most globals here to avoid naming conflicts. */


function md5_array(n) {
    for (var i = 0; i < n; i++) {
        this[i] = 0;
    }
    this.length = n;
}

/* Some basic logical functions had to be rewritten because of a bug in
 * Javascript.. Just try to compute 0xffffffff >> 4 with it..
 * Of course, these functions are slower than the original would be, but
 * at least, they work!
 */

function md5_integer(n) {
    return n % (0xffffffff + 1);
}

function md5_shr(a, b) {
    a = md5_integer(a);
    b = md5_integer(b);
    if (a - 0x80000000 >= 0) {
        a = a % 0x80000000;
        a >>= b;
        a += 0x40000000 >> (b - 1);
    } else {
        a >>= b;
    }
    return a;
}

function md5_shl1(a) {
    a = a % 0x80000000;
    if (a & 0x40000000 == 0x40000000) {
        a -= 0x40000000;
        a *= 2;
        a += 0x80000000;
    } else {
        a *= 2;
    }
    return a;
}

function md5_shl(a, b) {
    a = md5_integer(a);
    b = md5_integer(b);
    for (var i = 0; i < b; i++) {
        a = md5_shl1(a);
    }
    return a;
}

function md5_and(a, b) {
    a = md5_integer(a);
    b = md5_integer(b);
    var t1 = a - 0x80000000;
    var t2 = b - 0x80000000;
    if (t1 >= 0) {
        if (t2 >= 0) {
            return ((t1 & t2) + 0x80000000);
        } else {
            return (t1 & b);
        }
    } else {
        if (t2 >= 0) {
            return (a & t2);
        } else {
            return (a & b);
        }
    }
}

function md5_or(a, b) {
    a = md5_integer(a);
    b = md5_integer(b);
    var t1 = a - 0x80000000;
    var t2 = b - 0x80000000;
    if (t1 >= 0) {
        if (t2 >= 0) {
            return ((t1 | t2) + 0x80000000);
        } else {
            return ((t1 | b) + 0x80000000);
        }
    } else {
        if (t2 >= 0) {
            return ((a | t2) + 0x80000000);
        } else {
            return (a | b);
        }
    }
}

function md5_xor(a, b) {
    a = md5_integer(a);
    b = md5_integer(b);
    var t1 = a - 0x80000000;
    var t2 = b - 0x80000000;
    if (t1 >= 0) {
        if (t2 >= 0) {
            return (t1 ^ t2);
        } else {
            return ((t1 ^ b) + 0x80000000);
        }
    } else {
        if (t2 >= 0) {
            return ((a ^ t2) + 0x80000000);
        } else {
            return (a ^ b);
        }
    }
}

function md5_not(a) {
    a = md5_integer(a);
    return 0xffffffff - a;
}

/* Here begin the real algorithm */

var md5_state = new md5_array(4);
var md5_count = new md5_array(2);
    md5_count[0] = 0;
    md5_count[1] = 0;
var md5_buffer = new md5_array(64);
var md5_transformBuffer = new md5_array(16);
var md5_digestBits = new md5_array(16);

var md5_S11 = 7;
var md5_S12 = 12;
var md5_S13 = 17;
var md5_S14 = 22;
var md5_S21 = 5;
var md5_S22 = 9;
var md5_S23 = 14;
var md5_S24 = 20;
var md5_S31 = 4;
var md5_S32 = 11;
var md5_S33 = 16;
var md5_S34 = 23;
var md5_S41 = 6;
var md5_S42 = 10;
var md5_S43 = 15;
var md5_S44 = 21;

function md5_F(x, y, z) {
    return md5_or(md5_and(x, y), md5_and(md5_not(x), z));
}

function md5_G(x, y, z) {
    return md5_or(md5_and(x, z), md5_and(y, md5_not(z)));
}

function H(x, y, z) {
    return md5_xor(md5_xor(x, y), z);
}

function I(x, y, z) {
    return md5_xor(y, md5_or(x, md5_not(z)));
}

function md5_rotateLeft(a, n) {
    return md5_or(md5_shl(a, n), (md5_shr(a, (32 - n))));
}

function md5_FF(a, b, c, d, x, s, ac) {
    a = a + md5_F(b, c, d) + x + ac;
    a = md5_rotateLeft(a, s);
    a = a + b;
    return a;
}

function md5_GG(a, b, c, d, x, s, ac) {
    a = a + md5_G(b, c, d) + x + ac;
    a = md5_rotateLeft(a, s);
    a = a + b;
    return a;
}

function md5_HH(a, b, c, d, x, s, ac) {
    a = a + H(b, c, d) + x + ac;
    a = md5_rotateLeft(a, s);
    a = a + b;
    return a;
}

function md5_II(a, b, c, d, x, s, ac) {
    a = a + I(b, c, d) + x + ac;
    a = md5_rotateLeft(a, s);
    a = a + b;
    return a;
}

function md5_transform(buf, offset) {
    var a = 0, b = 0, c = 0, d = 0;
    var x = md5_transformBuffer;

    a = md5_state[0];
    b = md5_state[1];
    c = md5_state[2];
    d = md5_state[3];

    for (var i = 0; i < 16; i++) {
        x[i] = md5_and(buf[i * 4 + offset], 0xFF);
        for (var j = 1; j < 4; j++) {
            x[i] += md5_shl(md5_and(buf[i * 4 + j + offset] ,0xFF), j * 8);
        }
    }

    /* Round 1 */
    a = md5_FF( a, b, c, d, x[ 0], md5_S11, 0xd76aa478); /* 1 */
    d = md5_FF( d, a, b, c, x[ 1], md5_S12, 0xe8c7b756); /* 2 */
    c = md5_FF( c, d, a, b, x[ 2], md5_S13, 0x242070db); /* 3 */
    b = md5_FF( b, c, d, a, x[ 3], md5_S14, 0xc1bdceee); /* 4 */
    a = md5_FF( a, b, c, d, x[ 4], md5_S11, 0xf57c0faf); /* 5 */
    d = md5_FF( d, a, b, c, x[ 5], md5_S12, 0x4787c62a); /* 6 */
    c = md5_FF( c, d, a, b, x[ 6], md5_S13, 0xa8304613); /* 7 */
    b = md5_FF( b, c, d, a, x[ 7], md5_S14, 0xfd469501); /* 8 */
    a = md5_FF( a, b, c, d, x[ 8], md5_S11, 0x698098d8); /* 9 */
    d = md5_FF( d, a, b, c, x[ 9], md5_S12, 0x8b44f7af); /* 10 */
    c = md5_FF( c, d, a, b, x[10], md5_S13, 0xffff5bb1); /* 11 */
    b = md5_FF( b, c, d, a, x[11], md5_S14, 0x895cd7be); /* 12 */
    a = md5_FF( a, b, c, d, x[12], md5_S11, 0x6b901122); /* 13 */
    d = md5_FF( d, a, b, c, x[13], md5_S12, 0xfd987193); /* 14 */
    c = md5_FF( c, d, a, b, x[14], md5_S13, 0xa679438e); /* 15 */
    b = md5_FF( b, c, d, a, x[15], md5_S14, 0x49b40821); /* 16 */

    /* Round 2 */
    a = md5_GG( a, b, c, d, x[ 1], md5_S21, 0xf61e2562); /* 17 */
    d = md5_GG( d, a, b, c, x[ 6], md5_S22, 0xc040b340); /* 18 */
    c = md5_GG( c, d, a, b, x[11], md5_S23, 0x265e5a51); /* 19 */
    b = md5_GG( b, c, d, a, x[ 0], md5_S24, 0xe9b6c7aa); /* 20 */
    a = md5_GG( a, b, c, d, x[ 5], md5_S21, 0xd62f105d); /* 21 */
    d = md5_GG( d, a, b, c, x[10], md5_S22,  0x2441453); /* 22 */
    c = md5_GG( c, d, a, b, x[15], md5_S23, 0xd8a1e681); /* 23 */
    b = md5_GG( b, c, d, a, x[ 4], md5_S24, 0xe7d3fbc8); /* 24 */
    a = md5_GG( a, b, c, d, x[ 9], md5_S21, 0x21e1cde6); /* 25 */
    d = md5_GG( d, a, b, c, x[14], md5_S22, 0xc33707d6); /* 26 */
    c = md5_GG( c, d, a, b, x[ 3], md5_S23, 0xf4d50d87); /* 27 */
    b = md5_GG( b, c, d, a, x[ 8], md5_S24, 0x455a14ed); /* 28 */
    a = md5_GG( a, b, c, d, x[13], md5_S21, 0xa9e3e905); /* 29 */
    d = md5_GG( d, a, b, c, x[ 2], md5_S22, 0xfcefa3f8); /* 30 */
    c = md5_GG( c, d, a, b, x[ 7], md5_S23, 0x676f02d9); /* 31 */
    b = md5_GG( b, c, d, a, x[12], md5_S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    a = md5_HH( a, b, c, d, x[ 5], md5_S31, 0xfffa3942); /* 33 */
    d = md5_HH( d, a, b, c, x[ 8], md5_S32, 0x8771f681); /* 34 */
    c = md5_HH( c, d, a, b, x[11], md5_S33, 0x6d9d6122); /* 35 */
    b = md5_HH( b, c, d, a, x[14], md5_S34, 0xfde5380c); /* 36 */
    a = md5_HH( a, b, c, d, x[ 1], md5_S31, 0xa4beea44); /* 37 */
    d = md5_HH( d, a, b, c, x[ 4], md5_S32, 0x4bdecfa9); /* 38 */
    c = md5_HH( c, d, a, b, x[ 7], md5_S33, 0xf6bb4b60); /* 39 */
    b = md5_HH( b, c, d, a, x[10], md5_S34, 0xbebfbc70); /* 40 */
    a = md5_HH( a, b, c, d, x[13], md5_S31, 0x289b7ec6); /* 41 */
    d = md5_HH( d, a, b, c, x[ 0], md5_S32, 0xeaa127fa); /* 42 */
    c = md5_HH( c, d, a, b, x[ 3], md5_S33, 0xd4ef3085); /* 43 */
    b = md5_HH( b, c, d, a, x[ 6], md5_S34,  0x4881d05); /* 44 */
    a = md5_HH( a, b, c, d, x[ 9], md5_S31, 0xd9d4d039); /* 45 */
    d = md5_HH( d, a, b, c, x[12], md5_S32, 0xe6db99e5); /* 46 */
    c = md5_HH( c, d, a, b, x[15], md5_S33, 0x1fa27cf8); /* 47 */
    b = md5_HH( b, c, d, a, x[ 2], md5_S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    a = md5_II( a, b, c, d, x[ 0], md5_S41, 0xf4292244); /* 49 */
    d = md5_II( d, a, b, c, x[ 7], md5_S42, 0x432aff97); /* 50 */
    c = md5_II( c, d, a, b, x[14], md5_S43, 0xab9423a7); /* 51 */
    b = md5_II( b, c, d, a, x[ 5], md5_S44, 0xfc93a039); /* 52 */
    a = md5_II( a, b, c, d, x[12], md5_S41, 0x655b59c3); /* 53 */
    d = md5_II( d, a, b, c, x[ 3], md5_S42, 0x8f0ccc92); /* 54 */
    c = md5_II( c, d, a, b, x[10], md5_S43, 0xffeff47d); /* 55 */
    b = md5_II( b, c, d, a, x[ 1], md5_S44, 0x85845dd1); /* 56 */
    a = md5_II( a, b, c, d, x[ 8], md5_S41, 0x6fa87e4f); /* 57 */
    d = md5_II( d, a, b, c, x[15], md5_S42, 0xfe2ce6e0); /* 58 */
    c = md5_II( c, d, a, b, x[ 6], md5_S43, 0xa3014314); /* 59 */
    b = md5_II( b, c, d, a, x[13], md5_S44, 0x4e0811a1); /* 60 */
    a = md5_II( a, b, c, d, x[ 4], md5_S41, 0xf7537e82); /* 61 */
    d = md5_II( d, a, b, c, x[11], md5_S42, 0xbd3af235); /* 62 */
    c = md5_II( c, d, a, b, x[ 2], md5_S43, 0x2ad7d2bb); /* 63 */
    b = md5_II( b, c, d, a, x[ 9], md5_S44, 0xeb86d391); /* 64 */

    md5_state[0] += a;
    md5_state[1] += b;
    md5_state[2] += c;
    md5_state[3] += d;

}

function md5_init() {
    md5_count[0] = md5_count[1] = 0;
    md5_state[0] = 0x67452301;
    md5_state[1] = 0xefcdab89;
    md5_state[2] = 0x98badcfe;
    md5_state[3] = 0x10325476;
    for (var i = 0; i < md5_digestBits.length; i++) {
        md5_digestBits[i] = 0;
    }
}

function md5_update(b) {
    var index, i;

    index = md5_and(md5_shr(md5_count[0],3) , 0x3F);
    if (md5_count[0] < 0xFFFFFFFF - 7) {
      md5_count[0] += 8;
    } else {
      md5_count[1]++;
      md5_count[0] -= 0xFFFFFFFF + 1;
      md5_count[0] += 8;
    }
    md5_buffer[index] = md5_and(b, 0xff);
    if (index  >= 63) {
        md5_transform(md5_buffer, 0);
    }
}

function md5_finish() {
    var bits = new md5_array(8);
    var padding;
    var i = 0, index = 0, padLen = 0;

    for (i = 0; i < 4; i++) {
        bits[i] = md5_and(md5_shr(md5_count[0], (i * 8)), 0xFF);
    }
    for (i = 0; i < 4; i++) {
        bits[i + 4] = md5_and(md5_shr(md5_count[1], (i * 8)), 0xFF);
    }
    index = md5_and(md5_shr(md5_count[0], 3), 0x3F);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    padding = new md5_array(64);
    padding[0] = 0x80;
    for (i = 0; i < padLen; i++) {
      md5_update(padding[i]);
    }
    for (i = 0; i < 8; i++) {
      md5_update(bits[i]);
    }

    for (i = 0; i < 4; i++) {
        for (var j = 0; j < 4; j++) {
            md5_digestBits[i * 4 + j] = md5_and(md5_shr(md5_state[i], (j * 8)) , 0xFF);
        }
    }
}

/* End of the MD5 algorithm */
