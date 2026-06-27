fn process(hash: &mut [u32; 8], content: &[u8; 64]) {
    let [a, b, c, d, e, f, g, h] = hash;

    let (h1, h2) = unsafe {
        let a_init: [u32; 4] = hash[0..4].try_into().unwrap();
        let b_init: [u32; 4] = hash[4..8].try_into().unwrap();

        let mut A: [u32; 4] = a_init;
        let mut B: [u32; 4] = b_init;

        // W0..W15, four schedule words per vector.
        let mut m0 = load_be_u32x4(content, 0); // W0..W3
        let mut m1 = load_be_u32x4(content, 16); // W4..W7
        let mut m2 = load_be_u32x4(content, 32); // W8..W11
        let mut m3 = load_be_u32x4(content, 48); // W12..W15

        // Rounds 0..15.
        let wk = add4(m0, load_k4_at(&self.table, 0));
        rounds4(&mut A, &mut B, &wk);

        let wk = add4(m1, load_k4_at(&self.table, 4));
        rounds4(&mut A, &mut B, &wk);

        let wk = add4(m2, load_k4_at(&self.table, 8));
        rounds4(&mut A, &mut B, &wk);

        let wk = add4(m3, load_k4_at(&self.table, 12));
        rounds4(&mut A, &mut B, &wk);

        for block in 0..12 {
            let next = message_schedule_batch(&mut m0, &mut m1, &mut m2, &mut m3);

            let kt = load_k4_at(&self.table, 4 * block + 16);
            let k = add4(next, kt);

            // Computes 4 rounds
            rounds4(&mut A, &mut B, &k);

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
    hash = [a, b, c, d, e, f, g, h];
}

fn message_schedule_batch(m0: &[u32; 4], m1: &[u32; 4], m2: &[u32; 4], m3: &[u32; 4]) -> [u32; 4] {
    let m4_0 = u32::ssig1(m3[2]) + m2[1] + u32::ssig0(m0[1]) + m0[0];
    let m4_1 = u32::ssig1(m3[3]) + m2[2] + u32::ssig0(m0[2]) + m0[1];
    let m4_2 = u32::ssig1(m4_0) + m2[3] + u32::ssig0(m0[3]) + m0[2];
    let m4_3 = u32::ssig1(m4_1) + m3[0] + u32::ssig0(m1[0]) + m0[3];
    [m4_0, m4_1, m4_2, m4_3]
}

#[inline(always)]
fn rounds4(upper: &mut [u32; 4], lower: &mut [u32; 4], wk: &[u32; 4]) {
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

#[inline(always)]
fn load_k4_at(table: &[u32; 64], t: usize) -> [u32; 4] {
    [table[t], table[t + 1], table[t + 2], table[t + 3]]
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
