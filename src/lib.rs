#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::{uint32x4_t, vld1q_u32};
use std::arch::aarch64::{vsha256su0q_u32, vsha256su1q_u32};

// -------------------------------------------------
// Public interface for the lib
pub trait HasherAlg {
    type Output;
    // Public interface used to incrementaly hash bytes following an algorithm
    fn update(&mut self, input: impl AsRef<[u8]>);

    // Public interface finish the computation and return the computed hash
    fn finalize(&mut self) -> Self::Output;

    // hexdecimal representation of the computed hash
    fn dgst(contents: impl AsRef<[u8]>) -> String;
}

// Different strategies used for computing SHA algs
enum ProcessingStrategy {
    Seq,
    BatchSeq,
    SimdSeq,
    SimdBatch,
}

// Algorithm section
//
//
//
//
//
// Sha-256/224
struct CCSha256 {
    hash: [u32; 8],
    table: [u32; 64],
    buffer: Vec<u8>,
    message_len: u64,
}

// Init structure
impl CCSha256 {
    fn new() -> Self {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        const INITIAL: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        CCSha256 {
            hash: INITIAL,
            table: K,
            buffer: Vec::with_capacity(64),
            message_len: 0,
        }
    }
}

// Scalar version
impl CCSha256 {
    fn process_block_scalar(&mut self, content: &[u8; 64]) {
        let wt = Self::message_schedule_scalar(content);

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hash;

        for t in 0..64 {
            let t1 = h
                .wrapping_add(u32::bsig1(e))
                .wrapping_add(u32::ch(e, f, g))
                .wrapping_add(self.table[t])
                .wrapping_add(wt[t]);

            let t2 = u32::bsig0(a).wrapping_add(u32::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.hash = std::array::from_fn(|i| self.hash[i].wrapping_add([a, b, c, d, e, f, g, h][i]));
    }
    fn message_schedule_scalar(content: &[u8; 64]) -> [u32; 64] {
        let mut wt = [0u32; 64];

        for (i, word_bytes) in content.chunks_exact(4).enumerate() {
            wt[i] =
                u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        for t in 16..64 {
            wt[t] = u32::ssig1(wt[t - 2])
                .wrapping_add(wt[t - 7])
                .wrapping_add(u32::ssig0(wt[t - 15]))
                .wrapping_add(wt[t - 16]);
        }
        wt
    }
}

// BatchSeq,
impl CCSha256 {
    fn process_block_concurrent_scalar(&mut self, content: &[u8; 64]) {
        let [a, b, c, d, e, f, g, h] = self.hash;

        let (h1, h2) = unsafe {
            let a_init: [u32; 4] = self.hash[0..4].try_into().unwrap();
            let b_init: [u32; 4] = self.hash[4..8].try_into().unwrap();

            let mut A: [u32; 4] = a_init;
            let mut B: [u32; 4] = b_init;

            // W0..W15, four schedule words per vector.
            let mut m0 = load_be_u32x4_default(content, 0); // W0..W3
            let mut m1 = load_be_u32x4_default(content, 16); // W4..W7
            let mut m2 = load_be_u32x4_default(content, 32); // W8..W11
            let mut m3 = load_be_u32x4_default(content, 48); // W12..W15

            // Rounds 0..15.
            let wk = add4(m0, Self::k4_scalar(&self.table, 0));
            Self::rounds4_scalar(&mut A, &mut B, &wk);

            let wk = add4(m1, Self::k4_scalar(&self.table, 4));
            Self::rounds4_scalar(&mut A, &mut B, &wk);

            let wk = add4(m2, Self::k4_scalar(&self.table, 8));
            Self::rounds4_scalar(&mut A, &mut B, &wk);

            let wk = add4(m3, Self::k4_scalar(&self.table, 12));
            Self::rounds4_scalar(&mut A, &mut B, &wk);

            for block in 0..12 {
                let next = Self::message_schedule_batch(&mut m0, &mut m1, &mut m2, &mut m3);

                let kt = Self::k4_scalar(&self.table, 4 * block + 16);
                let k = add4(next, kt);

                // Computes 4 rounds
                Self::rounds4_scalar(&mut A, &mut B, &k);

                // Shift the message to compute on the next round
                m0 = m1;
                m1 = m2;
                m2 = m3;
                m3 = next;
            }

            A = add4(A, a_init);
            B = add4(B, b_init);
            (A, B)
        };

        let [e, f, g, h] = h2;
        let [a, b, c, d] = h1;
        self.hash = [a, b, c, d, e, f, g, h];
    }

    fn message_schedule_batch(
        m0: &[u32; 4],
        m1: &[u32; 4],
        m2: &[u32; 4],
        m3: &[u32; 4],
    ) -> [u32; 4] {
        let m4_0 = u32::ssig1(m3[2]) + m2[1] + u32::ssig0(m0[1]) + m0[0];
        let m4_1 = u32::ssig1(m3[3]) + m2[2] + u32::ssig0(m0[2]) + m0[1];
        let m4_2 = u32::ssig1(m4_0) + m2[3] + u32::ssig0(m0[3]) + m0[2];
        let m4_3 = u32::ssig1(m4_1) + m3[0] + u32::ssig0(m1[0]) + m0[3];
        [m4_0, m4_1, m4_2, m4_3]
    }

    #[inline(always)]
    fn rounds4_scalar(upper: &mut [u32; 4], lower: &mut [u32; 4], wk: &[u32; 4]) {
        let mut a = upper[0];
        let mut b = upper[1];
        let mut c = upper[2];
        let mut d = upper[3];

        let mut e = lower[0];
        let mut f = lower[1];
        let mut g = lower[2];
        let mut h = lower[3];

        for i in 0..4 {
            let t1 = h
                .wrapping_add(u32::ssig1(e))
                .wrapping_add(u32::ch(e, f, g))
                .wrapping_add(wk[i]);

            let t2 = u32::ssig0(a).wrapping_add(u32::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        upper[0] = a;
        upper[1] = b;
        upper[2] = c;
        upper[3] = d;

        lower[0] = e;
        lower[1] = f;
        lower[2] = g;
        lower[3] = h;
    }

    #[inline(always)]
    fn k4_scalar(table: &[u32; 64], t: usize) -> [u32; 4] {
        [table[t], table[t + 1], table[t + 2], table[t + 3]]
    }
}

// Simd Batch
impl CCSha256 {
    fn process_block_concurrent(&mut self, content: &[u8; 64]) {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("sha") {
                unsafe {
                    self.x86_process_block_concurrent(content);
                }
                return;
            }
        }

        #[cfg(target_arch = "aarch64")]
        {
            if std::arch::is_aarch64_feature_detected!("sha2") {
                unsafe {
                    self.arm_process_block_concurrent(content);
                }
                return;
            }
        }
        self.process_block_concurrent_scalar(content);
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    fn arm_process_block_concurrent(&mut self, content: &[u8; 64]) {
        let [a, b, c, d, e, f, g, h] = self.hash;

        let mut h1 = [0u32; 4];
        let mut h2 = [0u32; 4];

        unsafe {
            use std::arch::aarch64::{vaddq_u32, vld1q_u32, vst1q_u32};

            let a_init = vld1q_u32(self.hash[0..4].as_ptr());
            let b_init = vld1q_u32(self.hash[4..].as_ptr());

            let mut A = a_init;
            let mut B = b_init;

            // W0..W15, four schedule words per vector.
            let mut m0 = load_be_u32x4(content, 0); // W0..W3
            let mut m1 = load_be_u32x4(content, 16); // W4..W7
            let mut m2 = load_be_u32x4(content, 32); // W8..W11
            let mut m3 = load_be_u32x4(content, 48); // W12..W15

            // Rounds 0..15.
            let wk = vaddq_u32(m0, load_k4(&self.table, 0));
            Self::arm_rounds4(&mut A, &mut B, &wk);

            let wk = vaddq_u32(m1, load_k4(&self.table, 4));
            Self::arm_rounds4(&mut A, &mut B, &wk);

            let wk = vaddq_u32(m2, load_k4(&self.table, 8));
            Self::arm_rounds4(&mut A, &mut B, &wk);

            let wk = vaddq_u32(m3, load_k4(&self.table, 12));
            Self::arm_rounds4(&mut A, &mut B, &wk);

            for block in 0..12 {
                let next =
                    Self::arm_message_schedule_simd_batch(&mut m0, &mut m1, &mut m2, &mut m3);

                let kt = load_k4(&self.table, 4 * block + 16);
                let k = vaddq_u32(next, kt);

                // Computes 4 rounds
                Self::arm_rounds4(&mut A, &mut B, &k);

                // Shift the message to compute on the next round
                m0 = m1;
                m1 = m2;
                m2 = m3;
                m3 = next;
            }

            A = vaddq_u32(A, a_init);
            B = vaddq_u32(B, b_init);

            vst1q_u32(h1.as_mut_ptr().add(0) as *mut u32, A);
            vst1q_u32(h2.as_mut_ptr().add(0) as *mut u32, B);
        }

        let [e, f, g, h] = h2;
        let [a, b, c, d] = h1;
        self.hash = [a, b, c, d, e, f, g, h];
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    #[target_feature(enable = "sha2")]
    unsafe fn arm_message_schedule_simd_batch(
        m0: &mut uint32x4_t,
        m1: &mut uint32x4_t,
        m2: &mut uint32x4_t,
        m3: &mut uint32x4_t,
    ) -> uint32x4_t {
        let lower = vsha256su0q_u32(*m0, *m1);
        vsha256su1q_u32(lower, *m2, *m3)
    }

    // Batch processing for x86
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "sha")]
    #[inline]
    unsafe fn x86_process_block_concurrent(&mut self, content: &[u8; 64]) {
        let [a, b, c, d, e, f, g, h] = self.hash;

        let mut h1 = [0u32; 4];
        let mut h2 = [0u32; 4];

        let a_init = _mm_set_epi32(c as i32, d as i32, g as i32, h as i32);
        let b_init = _mm_set_epi32(a as i32, b as i32, e as i32, f as i32);

        let mut A = a_init;
        let mut B = b_init;

        // W0..W15, four schedule words per vector.
        let mut m0 = load_be_m128i(content, 0); // W0..W3
        let mut m1 = load_be_m128i(content, 16); // W4..W7
        let mut m2 = load_be_m128i(content, 32); // W8..W11
        let mut m3 = load_be_m128i(content, 48); // W12..W15

        // Rounds 0..15.
        let wk = _mm_add_epi32(m0, load_k4(&self.table, 0));
        Self::x86_rounds4(&mut A, &mut B, &wk);

        let wk = _mm_add_epi32(m1, load_k4(&self.table, 4));
        Self::x86_rounds4(&mut A, &mut B, &wk);

        let wk = _mm_add_epi32(m2, load_k4(&self.table, 8));
        Self::x86_rounds4(&mut A, &mut B, &wk);

        let wk = _mm_add_epi32(m3, load_k4(&self.table, 12));
        Self::x86_rounds4(&mut A, &mut B, &wk);

        for block in 0..12 {
            let next = Self::x86_message_schedule_simd_batch(&mut m0, &mut m1, &mut m2, &mut m3);

            let kt = load_k4(&self.table, 4 * block + 16);
            let k = _mm_add_epi32(next, kt);

            // Computes 4 rounds
            Self::x86_rounds4(&mut A, &mut B, &k);

            // Shift the message to compute on the next round
            m0 = m1;
            m1 = m2;
            m2 = m3;
            m3 = next;
        }

        A = _mm_add_epi32(A, a_init);
        B = _mm_add_epi32(B, b_init);

        _mm_storeu_si128(h1.as_mut_ptr().add(0) as *mut __m128i, A);
        _mm_storeu_si128(h2.as_mut_ptr().add(0) as *mut __m128i, B);

        let [f, e, b, a] = h2;
        let [h, g, d, c] = h1;
        self.hash = [a, b, c, d, e, f, g, h];
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    #[target_feature(enable = "sha")]
    unsafe fn x86_message_schedule_simd_batch(
        m0: &mut __m128i,
        m1: &mut __m128i,
        m2: &mut __m128i,
        m3: &mut __m128i,
    ) -> __m128i {
        let mut sigma0 = _mm_sha256msg1_epu32(*m0, *m1);

        let x = _mm_alignr_epi8(*m3, *m2, 4);
        sigma0 = _mm_add_epi32(sigma0, x);

        _mm_sha256msg2_epu32(sigma0, *m3)
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[inline]
    #[target_feature(enable = "sha")]
    unsafe fn x86_rounds4(a: &mut __m128i, b: &mut __m128i, wk: &__m128i) {
        let mut tmp = _mm_sha256rnds2_epu32(*a, *b, *wk);
        *a = *b;
        *b = tmp;

        let wk_hi = _mm_srli_si128(*wk, 8);
        tmp = _mm_sha256rnds2_epu32(*a, *b, wk_hi);
        *a = *b;
        *b = tmp;
    }

    #[cfg(target_arch = "aarch64")]
    #[inline]
    #[target_feature(enable = "sha2")]
    unsafe fn arm_rounds4(a: &mut uint32x4_t, b: &mut uint32x4_t, wk: &uint32x4_t) {
        use std::arch::aarch64::{vsha256h2q_u32, vsha256hq_u32};

        let old_upper = *a;
        let new_upper = vsha256hq_u32(*a, *b, *wk);

        let new_lower = vsha256h2q_u32(*b, old_upper, *wk);

        *a = new_upper;
        *b = new_lower;
    }
}

// Utility functions used in the calculation of the algs
#[inline]
fn Fm(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

#[inline]
fn Gm(b: u32, c: u32, d: u32) -> u32 {
    (b & d) | (c & !d)
}

#[inline]
fn Hm(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

#[inline]
fn Im(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b | (!d))
}

trait Word: Sized {
    const BITS: u32;
    fn shr<const N: u32>(self) -> Self;
    fn rotr<const N: u32>(self) -> Self;
    fn rotl<const N: u32>(self) -> Self;

    fn ch(x: Self, y: Self, z: Self) -> Self;
    fn maj(x: Self, y: Self, z: Self) -> Self;
    fn bsig0(x: Self) -> Self;
    fn bsig1(x: Self) -> Self;
    fn ssig0(x: Self) -> Self;
    fn ssig1(x: Self) -> Self;
}

impl Word for u32 {
    const BITS: u32 = 32;

    fn shr<const N: u32>(self) -> Self {
        const { assert!(N < Self::BITS) };
        self >> N
    }

    fn rotr<const N: u32>(self) -> Self {
        const { assert!(N < Self::BITS) };
        (self >> N) | (self << (Self::BITS - N))
    }

    fn rotl<const N: u32>(self) -> Self {
        const { assert!(N < Self::BITS) };
        (self << N) | (self >> (Self::BITS - N))
    }

    fn ch(x: Self, y: Self, z: Self) -> Self {
        (x & y) ^ ((!x) & z)
    }
    fn maj(x: Self, y: Self, z: Self) -> Self {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn bsig0(x: Self) -> Self {
        x.rotr::<2>() ^ x.rotr::<13>() ^ x.rotr::<22>()
    }
    fn bsig1(x: Self) -> Self {
        x.rotr::<6>() ^ x.rotr::<11>() ^ x.rotr::<25>()
    }
    fn ssig0(x: Self) -> Self {
        x.rotr::<7>() ^ x.rotr::<18>() ^ x.shr::<3>()
    }
    fn ssig1(x: Self) -> Self {
        x.rotr::<17>() ^ x.rotr::<19>() ^ x.shr::<10>()
    }
}

impl Word for u64 {
    const BITS: u32 = 64;

    fn shr<const N: u32>(self) -> Self {
        const { assert!(N < Self::BITS) };
        self >> N
    }

    fn rotr<const N: u32>(self) -> Self {
        const { assert!(N < Self::BITS) };
        (self >> N) | (self << (Self::BITS - N))
    }
    fn rotl<const N: u32>(self) -> Self {
        const { assert!(N < Self::BITS) };
        (self << N) | (self >> (Self::BITS - N))
    }

    fn ch(x: Self, y: Self, z: Self) -> Self {
        (x & y) ^ ((!x) & z)
    }
    fn maj(x: Self, y: Self, z: Self) -> Self {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn bsig0(x: Self) -> Self {
        x.rotr::<28>() ^ x.rotr::<34>() ^ x.rotr::<39>()
    }
    fn bsig1(x: Self) -> Self {
        x.rotr::<14>() ^ x.rotr::<18>() ^ x.rotr::<41>()
    }
    fn ssig0(x: Self) -> Self {
        x.rotr::<1>() ^ x.rotr::<8>() ^ x.shr::<7>()
    }
    fn ssig1(x: Self) -> Self {
        x.rotr::<19>() ^ x.rotr::<61>() ^ x.shr::<6>()
    }
}

#[inline(always)]
fn add4(a: [u32; 4], b: [u32; 4]) -> [u32; 4] {
    [
        a[0].wrapping_add(b[0]),
        a[1].wrapping_add(b[1]),
        a[2].wrapping_add(b[2]),
        a[3].wrapping_add(b[3]),
    ]
}

#[inline]
fn load_be_u32x4_default(content: &[u8; 64], offset: usize) -> [u32; 4] {
    let w0 = u32::from_be_bytes([
        content[offset],
        content[offset + 1],
        content[offset + 2],
        content[offset + 3],
    ]);

    let w1 = u32::from_be_bytes([
        content[offset + 4],
        content[offset + 5],
        content[offset + 6],
        content[offset + 7],
    ]);

    let w2 = u32::from_be_bytes([
        content[offset + 8],
        content[offset + 9],
        content[offset + 10],
        content[offset + 11],
    ]);

    let w3 = u32::from_be_bytes([
        content[offset + 12],
        content[offset + 13],
        content[offset + 14],
        content[offset + 15],
    ]);

    [w0, w1, w2, w3]
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn load_k4(table: &[u32; 64], offset: usize) -> uint32x4_t {
    vld1q_u32(table[offset..offset + 4].as_ptr())
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
unsafe fn load_k4(table: &[u32; 64], t: usize) -> __m128i {
    _mm_set_epi32(
        table[t + 3] as i32,
        table[t + 2] as i32,
        table[t + 1] as i32,
        table[t] as i32,
    )
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn load_be_u32x4(content: &[u8; 64], offset: usize) -> uint32x4_t {
    let w0 = u32::from_be_bytes([
        content[offset],
        content[offset + 1],
        content[offset + 2],
        content[offset + 3],
    ]);

    let w1 = u32::from_be_bytes([
        content[offset + 4],
        content[offset + 5],
        content[offset + 6],
        content[offset + 7],
    ]);

    let w2 = u32::from_be_bytes([
        content[offset + 8],
        content[offset + 9],
        content[offset + 10],
        content[offset + 11],
    ]);

    let w3 = u32::from_be_bytes([
        content[offset + 12],
        content[offset + 13],
        content[offset + 14],
        content[offset + 15],
    ]);

    unsafe { vld1q_u32([w0, w1, w2, w3].as_ptr()) }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
unsafe fn load_be_m128i(content: &[u8; 64], offset: usize) -> __m128i {
    let w0 = u32::from_be_bytes([
        content[offset],
        content[offset + 1],
        content[offset + 2],
        content[offset + 3],
    ]);

    let w1 = u32::from_be_bytes([
        content[offset + 4],
        content[offset + 5],
        content[offset + 6],
        content[offset + 7],
    ]);

    let w2 = u32::from_be_bytes([
        content[offset + 8],
        content[offset + 9],
        content[offset + 10],
        content[offset + 11],
    ]);

    let w3 = u32::from_be_bytes([
        content[offset + 12],
        content[offset + 13],
        content[offset + 14],
        content[offset + 15],
    ]);

    _mm_set_epi32(w3 as i32, w2 as i32, w1 as i32, w0 as i32)
}
