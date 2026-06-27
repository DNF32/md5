#[cfg(target_arch = "aarch64")]
#[inline]
fn process(hash: &mut [u32; 8], content: &[u8; 64]) {
    let [a, b, c, d, e, f, g, h] = hash;

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
        let wk = vaddq_u32(m0, load_k4_at(&self.table, 0));
        rounds4(&mut A, &mut B, &wk);

        let wk = vaddq_u32(m1, load_k4_at(&self.table, 4));
        rounds4(&mut A, &mut B, &wk);

        let wk = vaddq_u32(m2, load_k4_at(&self.table, 8));
        rounds4(&mut A, &mut B, &wk);

        let wk = vaddq_u32(m3, load_k4_at(&self.table, 12));
        rounds4(&mut A, &mut B, &wk);

        for block in 0..12 {
            let next = message_schedule(&mut m0, &mut m1, &mut m2, &mut m3);

            let kt = load_k4_at(&self.table, 4 * block + 16);
            let k = vaddq_u32(next, kt);

            // Computes 4 rounds
            rounds4(&mut A, &mut B, &k);

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
    hash = [a, b, c, d, e, f, g, h];
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "sha2")]
unsafe fn rounds4(a: &mut uint32x4_t, b: &mut uint32x4_t, wk: &uint32x4_t) {
    use std::arch::aarch64::{vsha256h2q_u32, vsha256hq_u32};

    let old_upper = *a;
    let new_upper = vsha256hq_u32(*a, *b, *wk);

    let new_lower = vsha256h2q_u32(*b, old_upper, *wk);

    *a = new_upper;
    *b = new_lower;
}

#[cfg(target_arch = "aarch64")]
#[inline]
#[target_feature(enable = "sha2")]
unsafe fn message_schedule(
    m0: &mut uint32x4_t,
    m1: &mut uint32x4_t,
    m2: &mut uint32x4_t,
    m3: &mut uint32x4_t,
) -> uint32x4_t {
    let lower = vsha256su0q_u32(*m0, *m1);
    vsha256su1q_u32(lower, *m2, *m3)
}

#[inline]
fn load_be_u32x4(content: &[u8; 64], offset: usize) -> [u32; 4] {
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
unsafe fn load_k4_at(table: &[u32; 64], offset: usize) -> uint32x4_t {
    vld1q_u32(table[offset..offset + 4].as_ptr())
}
