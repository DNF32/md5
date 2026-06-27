#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sha")]
#[inline]
unsafe fn x86_process_block_concurrent(hash: &mut [u32; 8], content: &[u8; 64]) {
    let [a, b, c, d, e, f, g, h] = hash;

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
    let wk = _mm_add_epi32(m0, load_k4_at(&self.table, 0));
    x86_rounds4(&mut A, &mut B, &wk);

    let wk = _mm_add_epi32(m1, load_k4_at(&self.table, 4));
    x86_rounds4(&mut A, &mut B, &wk);

    let wk = _mm_add_epi32(m2, load_k4_at(&self.table, 8));
    x86_rounds4(&mut A, &mut B, &wk);

    let wk = _mm_add_epi32(m3, load_k4_at(&self.table, 12));
    x86_rounds4(&mut A, &mut B, &wk);

    for block in 0..12 {
        let next = x86_message_schedule_simd_batch(&mut m0, &mut m1, &mut m2, &mut m3);

        let kt = load_k4_at(&self.table, 4 * block + 16);
        let k = _mm_add_epi32(next, kt);

        // Computes 4 rounds
        x86_rounds4(&mut A, &mut B, &k);

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
    hash = [a, b, c, d, e, f, g, h];
}

// Given the the previous 4 message this returns the next message
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

// This function performs 4 rounds of sha256 mixing
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

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[inline]
unsafe fn load_k4_at(table: &[u32; 64], t: usize) -> __m128i {
    _mm_set_epi32(
        table[t + 3] as i32,
        table[t + 2] as i32,
        table[t + 1] as i32,
        table[t] as i32,
    )
}
