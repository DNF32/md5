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

// I think this might be from the md5
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
