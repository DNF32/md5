use core::arch::x86_64::*;
use md5::digest::consts::True;
use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Read};

use std::env;
use std::process;

struct Config {
    b_flag: bool,
    c_flag: bool,
    mine: bool,
    quiet_flag: bool,
    alg: String,
}

struct ErrorCount {
    inc_format: u32,
    inc_digest: u32,
}

impl ErrorCount {
    fn new() -> Self {
        ErrorCount {
            inc_format: 0,
            inc_digest: 0,
        }
    }
}

#[derive(Debug)]
enum File {
    StdIn,
    FilePath(String),
}
#[derive(Debug)]
enum Error {
    UnableToOpen(String),
}

impl From<String> for File {
    fn from(value: String) -> Self {
        if value == "-" {
            Self::StdIn
        } else {
            Self::FilePath(value)
        }
    }
}
impl From<&str> for File {
    fn from(value: &str) -> Self {
        if value == "-" {
            Self::StdIn
        } else {
            Self::FilePath(value.to_string())
        }
    }
}
impl File {
    fn to_name(&self) -> String {
        match &self {
            Self::StdIn => String::from("-"),
            Self::FilePath(path) => {
                let path_split: Vec<&str> = path.split("/").collect();
                String::from(path_split.last().copied().unwrap())
            }
        }
    }
    fn to_file_path(&self) -> String {
        match &self {
            Self::StdIn => String::from("std in"),
            Self::FilePath(path) => String::from(path.clone()),
        }
    }

    fn read_file(&self) -> Result<Vec<u8>, io::Error> {
        match self {
            Self::StdIn => {
                let mut buffer: Vec<u8> = Vec::new();
                io::stdin().read(&mut buffer)?;
                Ok(buffer)
            }
            Self::FilePath(path) => fs::read(path),
        }
    }

    fn read_file_as_str(&self) -> Result<String, io::Error> {
        match self {
            Self::StdIn => {
                let mut buffer: String = String::new();
                io::stdin().read_to_string(&mut buffer)?;
                Ok(buffer)
            }
            Self::FilePath(path) => fs::read_to_string(path),
        }
    }

    fn digest_file(&self, config: &Config) -> String {
        let spacer = if config.b_flag { " *" } else { "  " };

        if let Ok(digest) = self.digest(config) {
            format!("{}{}{}", digest, spacer, self.to_file_path())
            //dbg!(contents);
        } else {
            format!("Couldn't read file with path {}", self.to_file_path())
        }
    }

    fn digest(&self, config: &Config) -> Result<String, io::Error> {
        let content = self.read_file()?;
        if config.mine {
            Ok(digest_msg_mine(&content))
        } else if config.alg == "sha256" {
            Ok(digest_sha256_msg_mine(&content))
        } else if config.alg == "sha512" {
            Ok(digest_sha512_msg_mine(&content))
        } else {
            Ok(digest_msg(&content))
        }
    }

    fn validate_file(&self, config: &Config, error: &mut ErrorCount) -> String {
        let mut outs: Vec<String> = Vec::new();
        if let Ok(contents) = self.read_file_as_str() {
            for line in contents.lines() {
                let parts: Vec<&str> = line.split("  ").collect();
                if parts.len() >= 2 {
                    let first_option = parts[0];
                    let second_option = File::from(parts[1]);

                    let digest = second_option.digest(config);

                    match digest {
                        Ok(hex) if first_option == hex => {
                            if config.quiet_flag {
                                outs.push(format!("{}: OK", second_option.to_file_path()));
                            }
                        }
                        Ok(_) => {
                            outs.push(format!("{}: FAILED", second_option.to_file_path()));
                            error.inc_digest += 1;
                        }
                        Err(_) => outs.push(format!(
                            "md5sum:  {}: No such file or directory",
                            second_option.to_file_path()
                        )),
                    }
                    // use first_option / second_option here
                } else {
                    let parts: Vec<&str> = line.split(" *").collect();
                    if parts.len() <= 2 {
                        error.inc_format += 1;
                    } else {
                        let first_option = parts[0];
                        let second_option = File::from(parts[1]);
                        let digest = second_option.digest(config);

                        match digest {
                            Ok(hex) => {
                                if first_option == hex {
                                    outs.push(format!("{}: OK", second_option.to_file_path()));
                                } else {
                                    outs.push(format!("{}: WARNING", second_option.to_file_path()));
                                    error.inc_digest += 1;
                                }
                            }
                            Err(_) => outs.push(format!(
                                "md5sum:  {}: No such file or directory",
                                second_option.to_file_path()
                            )),
                        }
                    }
                }
            }
            outs.join("\n")
        } else {
            format!(
                "md5sum:  {}: No such file or directory",
                self.to_file_path()
            )
        }
    }
}

fn parse_flag(args: Vec<String>) -> (Config, Vec<File>) {
    let mut b_flag = false;
    let mut c_flag = false;
    let mut mine = false;
    let mut quiet_flag = false;
    let mut alg = String::new();
    let mut inputs: Vec<File> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-b" {
            b_flag = true;
        } else if arg == "-c" {
            c_flag = true
        } else if arg == "--quiet" {
            quiet_flag = true
        } else if arg == "--mine" {
            mine = true
        } else if arg == "--algorithm" {
            alg = args[i + 1].clone();
            i += 1;
        } else {
            inputs.push(File::from(arg.as_str()));
        }
        i += 1;
    }

    (
        Config {
            b_flag: b_flag,
            c_flag: c_flag,
            quiet_flag: quiet_flag,
            mine: mine,
            alg: alg,
        },
        inputs,
    )
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let (config, file_paths) = parse_flag(args);

    let mut err = ErrorCount::new();

    match config.c_flag {
        false => {
            let out = file_paths
                .iter()
                .map(|file| file.digest_file(&config))
                .collect::<Vec<String>>()
                .join("\n");
            println!("{out}");
        }
        true => {
            let out = file_paths
                .iter()
                .map(|file| file.validate_file(&config, &mut err))
                .collect::<Vec<String>>()
                .join("\n");
            println!("{out}");
            if err.inc_format > 0 {
                println!(
                    "md5sum: WARNING: {} line is improperly formatted",
                    err.inc_format
                );
            }
            if err.inc_digest > 0 {
                println!(
                    "md5sum: WARNING: {} computed checksum did NOT match",
                    err.inc_digest
                );
            }
        }
    }
}

fn digest_msg(contents: impl AsRef<[u8]>) -> String {
    let mut hasher = Md5::new();
    hasher.update(contents);
    let hash: [u8; 16] = hasher.finalize().into();
    let hash_hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();
    hash_hex
}

fn digest_msg_mine(contents: impl AsRef<[u8]>) -> String {
    let mut hasher = CCMd5::new();
    hasher.update(contents);
    let out = hasher.finalize();

    out.iter()
        .flat_map(|word| word.to_le_bytes())
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn digest_sha256_msg_mine(contents: impl AsRef<[u8]>) -> String {
    let mut hasher = CCSha256::new();
    hasher.update(contents);
    let out = hasher.finalize();
    out.iter().map(|byte| format!("{:08x}", byte)).collect()
}

fn digest_sha512_msg_mine(contents: impl AsRef<[u8]>) -> String {
    let mut hasher = CCSha512::new();
    hasher.update(contents);
    let out = hasher.finalize();
    out.iter().map(|byte| format!("{:016x}", byte)).collect()
}

const MAGIC: f64 = 4294967296.0;

fn make_table<const N: usize>() -> [u32; N] {
    let mut values = [0u32; N];

    for i in 0..N {
        values[i] = (MAGIC * ((i + 1) as f64).sin().abs()) as u32;
    }
    values
}

const fn make_k_index(start: usize, shift: usize) -> [usize; 16] {
    let mut buffer = [0usize; 16];

    let mut i = 0;
    while i < 16 {
        buffer[i] = (start + i * shift) % 16;
        i += 1;
    }
    buffer
}

impl CCMd5 {
    fn new() -> Self {
        let mut A: u32 = 0x67452301;
        let mut B: u32 = 0xefcdab89;
        let mut C: u32 = 0x98badcfe;
        let mut D: u32 = 0x10325476;

        CCMd5 {
            hash: [A, B, C, D],
            table: make_table::<64>(),
            state: State {
                values: [A, B, C, D],
                i: 0,
            },
            buffer: Vec::new(),
            message_len: 0,
        }
    }

    fn reset_state(&mut self) {
        let new_state = State {
            values: self.hash,
            i: 0,
        };
        self.state = new_state;
    }

    fn update_hash(&mut self) {
        self.hash = std::array::from_fn(|i| self.hash[i].wrapping_add(self.state.values[i]));
    }

    fn rot(&mut self) {
        let tmp = self.state.values[3];
        self.state.values[3] = self.state.values[2];
        self.state.values[2] = self.state.values[1];
        self.state.values[1] = self.state.values[0];
        self.state.values[0] = tmp;
    }

    fn round<F>(&mut self, block: &[u32; 16], k_v: [usize; 16], s_v: [u32; 4], f: &F)
    where
        F: Fn(u32, u32, u32) -> u32,
    {
        for i in 0..4 {
            self.block(k_v[i * 4], s_v[0], f, block);
            self.block(k_v[i * 4 + 1], s_v[1], f, block);
            self.block(k_v[i * 4 + 2], s_v[2], f, block);
            self.block(k_v[i * 4 + 3], s_v[3], f, block);
        }
    }

    fn block<F>(&mut self, k: usize, s: u32, f: F, x: &[u32; 16])
    where
        F: Fn(u32, u32, u32) -> u32,
    {
        self.state.values[0] = Self::mixer(&mut self.state, k, s, f, x, &self.table);
        self.state.i += 1;
        self.rot();
    }

    fn mixer<F>(state: &mut State, k: usize, s: u32, f: F, x: &[u32; 16], table: &[u32; 64]) -> u32
    where
        F: Fn(u32, u32, u32) -> u32,
    {
        //b + ((a + f(b, c, d) + x[k] + table[i]) << s)
        let f_res = f(state.values[1], state.values[2], state.values[3]);

        let sum = state.values[0]
            .wrapping_add(f_res)
            .wrapping_add(x[k])
            .wrapping_add(table[state.i]);

        let rot = sum.rotate_left(s);

        state.values[1].wrapping_add(rot)
    }

    fn process_block(&mut self, content: &[u8; 64]) {
        debug_assert_eq!(content.len(), 64);

        let mut buffer_msg = [0u32; 16];

        for (i, word_bytes) in content.chunks_exact(4).enumerate() {
            buffer_msg[i] =
                u32::from_le_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        self.reset_state();

        // Round 1
        self.round(&buffer_msg, make_k_index(0, 1), [7, 12, 17, 22], &Fm);

        // Round 2
        self.round(&buffer_msg, make_k_index(1, 5), [5, 9, 14, 20], &Gm);

        // Round 3
        self.round(&buffer_msg, make_k_index(5, 3), [4, 11, 16, 23], &Hm);

        // Round 4
        self.round(&buffer_msg, make_k_index(0, 7), [6, 10, 15, 21], &Im);

        self.update_hash();
    }

    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.message_len += input.len() as u64;
        self.buffer.extend_from_slice(input);

        while self.buffer.len() >= 64 {
            let block: Vec<u8> = self.buffer.drain(..64).collect();
            self.process_block(&block.try_into().unwrap());
        }
    }

    fn finalize(mut self) -> [u32; 4] {
        let bit_len = self.message_len * 8;

        self.buffer.push(0x80);

        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }

        self.buffer.extend_from_slice(&bit_len.to_le_bytes());

        let final_blocks = std::mem::take(&mut self.buffer);
        for block in final_blocks.chunks_exact(64) {
            self.process_block(block.try_into().unwrap());
        }

        self.hash
    }
}

struct CCMd5 {
    hash: [u32; 4],
    table: [u32; 64],
    state: State,
    buffer: Vec<u8>,
    message_len: u64,
}
struct State {
    values: [u32; 4],
    i: usize,
}

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

struct CCSha512 {
    hash: [u64; 8],
    table: [u64; 80],
    buffer: Vec<u8>,
    message_len: u128,
}

impl CCSha512 {
    fn new() -> Self {
        const K: [u64; 80] = [
            0x428a2f98d728ae22,
            0x7137449123ef65cd,
            0xb5c0fbcfec4d3b2f,
            0xe9b5dba58189dbbc,
            0x3956c25bf348b538,
            0x59f111f1b605d019,
            0x923f82a4af194f9b,
            0xab1c5ed5da6d8118,
            0xd807aa98a3030242,
            0x12835b0145706fbe,
            0x243185be4ee4b28c,
            0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f,
            0x80deb1fe3b1696b1,
            0x9bdc06a725c71235,
            0xc19bf174cf692694,
            0xe49b69c19ef14ad2,
            0xefbe4786384f25e3,
            0x0fc19dc68b8cd5b5,
            0x240ca1cc77ac9c65,
            0x2de92c6f592b0275,
            0x4a7484aa6ea6e483,
            0x5cb0a9dcbd41fbd4,
            0x76f988da831153b5,
            0x983e5152ee66dfab,
            0xa831c66d2db43210,
            0xb00327c898fb213f,
            0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2,
            0xd5a79147930aa725,
            0x06ca6351e003826f,
            0x142929670a0e6e70,
            0x27b70a8546d22ffc,
            0x2e1b21385c26c926,
            0x4d2c6dfc5ac42aed,
            0x53380d139d95b3df,
            0x650a73548baf63de,
            0x766a0abb3c77b2a8,
            0x81c2c92e47edaee6,
            0x92722c851482353b,
            0xa2bfe8a14cf10364,
            0xa81a664bbc423001,
            0xc24b8b70d0f89791,
            0xc76c51a30654be30,
            0xd192e819d6ef5218,
            0xd69906245565a910,
            0xf40e35855771202a,
            0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8,
            0x1e376c085141ab53,
            0x2748774cdf8eeb99,
            0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63,
            0x4ed8aa4ae3418acb,
            0x5b9cca4f7763e373,
            0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc,
            0x78a5636f43172f60,
            0x84c87814a1f0ab72,
            0x8cc702081a6439ec,
            0x90befffa23631e28,
            0xa4506cebde82bde9,
            0xbef9a3f7b2c67915,
            0xc67178f2e372532b,
            0xca273eceea26619c,
            0xd186b8c721c0c207,
            0xeada7dd6cde0eb1e,
            0xf57d4f7fee6ed178,
            0x06f067aa72176fba,
            0x0a637dc5a2c898a6,
            0x113f9804bef90dae,
            0x1b710b35131c471b,
            0x28db77f523047d84,
            0x32caab7b40c72493,
            0x3c9ebe0a15c9bebc,
            0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6,
            0x597f299cfc657e2a,
            0x5fcb6fab3ad6faec,
            0x6c44198c4a475817,
        ];
        const INITIAL: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        CCSha512 {
            hash: INITIAL,
            table: K,
            buffer: Vec::with_capacity(128),
            message_len: 0,
        }
    }

    fn message_schedule_scalar(content: &[u8; 128]) -> [u64; 80] {
        let mut wt = [0u64; 80];

        for (i, word_bytes) in content.chunks_exact(8).enumerate() {
            wt[i] = u64::from_be_bytes([
                word_bytes[0],
                word_bytes[1],
                word_bytes[2],
                word_bytes[3],
                word_bytes[4],
                word_bytes[5],
                word_bytes[6],
                word_bytes[7],
            ]);
        }

        for t in 16..80 {
            wt[t] = u64::ssig1(wt[t - 2])
                .wrapping_add(wt[t - 7])
                .wrapping_add(u64::ssig0(wt[t - 15]))
                .wrapping_add(wt[t - 16]);
        }
        wt
    }

    fn process_block_scalar(&mut self, content: &[u8; 128]) {
        let wt = Self::message_schedule_scalar(content);

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hash;

        for t in 0..80 {
            let t1 = h
                .wrapping_add(u64::bsig1(e))
                .wrapping_add(u64::ch(e, f, g))
                .wrapping_add(self.table[t])
                .wrapping_add(wt[t]);

            let t2 = u64::bsig0(a).wrapping_add(u64::maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.update_hash([a, b, c, d, e, f, g, h]);
    }

    fn update_hash(&mut self, state: [u64; 8]) {
        self.hash = std::array::from_fn(|i| self.hash[i].wrapping_add(state[i]));
    }

    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.message_len += input.len() as u128;

        let buffer_size = self.buffer.len();

        if buffer_size + input.len() < 128 {
            self.buffer.extend_from_slice(input);
            return;
        }

        let take = 128 - buffer_size;
        let mut offset = take;

        self.buffer.extend_from_slice(&input[0..offset]);
        //assert!(self.buffer.len() == 128);

        let mut buffer = std::mem::take(&mut self.buffer);
        let base_block = buffer.as_slice().try_into().unwrap();
        self.process_block_scalar(base_block);

        while input.len() - offset >= 128 {
            let block = &input[offset..(offset + 128)];
            self.process_block_scalar(block.try_into().unwrap());
            offset += 128;
        }

        buffer.clear();
        buffer.extend_from_slice(&input[offset..]);
        self.buffer = buffer;
    }

    fn finalize(mut self) -> [u64; 8] {
        let bit_len = self.message_len * 8;

        self.buffer.push(0x80);

        while self.buffer.len() % 128 != 112 {
            self.buffer.push(0);
        }

        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        let final_blocks = std::mem::take(&mut self.buffer);
        for block in final_blocks.chunks_exact(128) {
            self.process_block_scalar(block.try_into().unwrap());
        }

        self.hash
    }
}

struct CCSha256 {
    hash: [u32; 8],
    table: [u32; 64],
    buffer: Vec<u8>,
    message_len: u64,
}

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

    #[inline]
    unsafe fn k4(table: &[u32; 64], t: usize) -> __m128i {
        _mm_set_epi32(
            table[t + 3] as i32,
            table[t + 2] as i32,
            table[t + 1] as i32,
            table[t] as i32,
        )
    }

    #[inline]
    unsafe fn load4_be(content: &[u8; 64], offset: usize) -> __m128i {
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

    #[inline]
    unsafe fn process_block_concurrent(&mut self, content: &[u8; 64]) {
        let [a, b, c, d, e, f, g, h] = self.hash;

        let mut h1 = [0u32; 4];
        let mut h2 = [0u32; 4];

        let a_init = _mm_set_epi32(c as i32, d as i32, g as i32, h as i32);
        let b_init = _mm_set_epi32(a as i32, b as i32, e as i32, f as i32);

        let mut A = a_init;
        let mut B = b_init;

        // W0..W15, four schedule words per vector.
        let mut m0 = Self::load4_be(content, 0); // W0..W3
        let mut m1 = Self::load4_be(content, 16); // W4..W7
        let mut m2 = Self::load4_be(content, 32); // W8..W11
        let mut m3 = Self::load4_be(content, 48); // W12..W15

        // Rounds 0..15.
        let wk = _mm_add_epi32(m0, Self::k4(&self.table, 0));
        Self::rounds4(&mut A, &mut B, &wk);

        let wk = _mm_add_epi32(m1, Self::k4(&self.table, 4));
        Self::rounds4(&mut A, &mut B, &wk);

        let wk = _mm_add_epi32(m2, Self::k4(&self.table, 8));
        Self::rounds4(&mut A, &mut B, &wk);

        let wk = _mm_add_epi32(m3, Self::k4(&self.table, 12));
        Self::rounds4(&mut A, &mut B, &wk);

        for block in 0..12 {
            let next = Self::schedule_message(&mut m0, &mut m1, &mut m2, &mut m3);

            let kt = Self::k4(&self.table, 4 * block + 16);
            let k = _mm_add_epi32(next, kt);

            // Computes 4 rounds
            Self::rounds4(&mut A, &mut B, &k);

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

    #[inline]
    #[target_feature(enable = "sha")]
    unsafe fn schedule_message(
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

    #[inline]
    #[target_feature(enable = "sha")]
    unsafe fn rounds4(a: &mut __m128i, b: &mut __m128i, wk: &__m128i) {
        let mut tmp = _mm_sha256rnds2_epu32(*a, *b, *wk);
        *a = *b;
        *b = tmp;

        let wk_hi = _mm_srli_si128(*wk, 8);
        tmp = _mm_sha256rnds2_epu32(*a, *b, wk_hi);
        *a = *b;
        *b = tmp;
    }

    //unsafe fn message_schedule_paralel(content: &[u8; 64]) -> [u32; 64] {
    //    let mut wt = [0u32; 64];

    //    for block in 0..12 {
    //        let t = 4 * block;

    //        let b0 = _mm_set_epi32(
    //            wt[t + 3] as i32,
    //            wt[t + 2] as i32,
    //            wt[t + 1] as i32,
    //            wt[t] as i32,
    //        );
    //        let b2 = _mm_set_epi32(
    //            wt[t + 8 + 3] as i32,
    //            wt[t + 8 + 2] as i32,
    //            wt[t + 8 + 1] as i32,
    //            wt[t + 8] as i32,
    //        );
    //        let b3 = _mm_set_epi32(
    //            wt[t + 12 + 3] as i32,
    //            wt[t + 12 + 2] as i32,
    //            wt[t + 12 + 1] as i32,
    //            wt[t + 12] as i32,
    //        );

    //        let b1_1 = _mm_set_epi32(0, 0, 0, wt[t + 4] as i32);
    //        let mut sigma0 = _mm_sha256msg1_epu32(b0, b1_1);

    //        let x = _mm_alignr_epi8(b3, b2, 4);
    //        sigma0 = _mm_add_epi32(sigma0, x);

    //        let sigma1 = _mm_sha256msg2_epu32(sigma0, b3);

    //        _mm_storeu_si128(wt.as_mut_ptr().add(t + 16) as *mut __m128i, sigma1);
    //    }
    //    wt
    //}
    //unsafe fn process_block_parallel(&mut self, content: &[u8; 64]) {
    //    let wt = Self::message_schedule_paralel(content);

    //    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.hash;

    //    let mut h1 = [0u32; 4];
    //    let mut h2 = [0u32; 4];

    //    let A_init = _mm_set_epi32(c as i32, d as i32, g as i32, h as i32);
    //    let B_init = _mm_set_epi32(a as i32, b as i32, e as i32, f as i32);

    //    let mut A = _mm_set_epi32(c as i32, d as i32, g as i32, h as i32);
    //    let mut B = _mm_set_epi32(a as i32, b as i32, e as i32, f as i32);

    //    for t in 0..32 {
    //        let k = _mm_set_epi32(
    //            0,
    //            0,
    //            self.table[2 * t + 1].wrapping_add(wt[2 * t + 1]) as i32,
    //            self.table[2 * t].wrapping_add(wt[2 * t]) as i32,
    //        );
    //        let inter = _mm_sha256rnds2_epu32(A, B, k);
    //        A = B;
    //        B = inter
    //    }
    //    A = _mm_add_epi32(A, A_init);
    //    B = _mm_add_epi32(B, B_init);

    //    _mm_storeu_si128(h1.as_mut_ptr().add(0) as *mut __m128i, A);
    //    _mm_storeu_si128(h2.as_mut_ptr().add(0) as *mut __m128i, B);

    //    let [f, e, b, a] = h2;
    //    let [h, g, d, c] = h1;
    //    self.hash = [a, b, c, d, e, f, g, h];
    //}

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
        self.update_hash([a, b, c, d, e, f, g, h]);
    }

    fn update_hash(&mut self, state: [u32; 8]) {
        self.hash = std::array::from_fn(|i| self.hash[i].wrapping_add(state[i]));
    }

    fn update(&mut self, input: impl AsRef<[u8]>) {
        let input = input.as_ref();
        self.message_len += input.len() as u64;

        let buffer_size = self.buffer.len();

        if buffer_size + input.len() < 64 {
            self.buffer.extend_from_slice(input);
            return;
        }

        let take = 64 - buffer_size;
        let mut offset = take;

        self.buffer.extend_from_slice(&input[0..offset]);
        //assert!(self.buffer.len() == 64);

        let mut buffer = std::mem::take(&mut self.buffer);
        let base_block = buffer.as_slice().try_into().unwrap();
        unsafe {
            self.process_block_concurrent(base_block);
        }

        while input.len() - offset >= 64 {
            let block = &input[offset..(offset + 64)];
            unsafe {
                self.process_block_concurrent(block.try_into().unwrap());
            }
            offset += 64;
        }

        buffer.clear();
        buffer.extend_from_slice(&input[offset..]);
        self.buffer = buffer;
    }

    fn finalize(mut self) -> [u32; 8] {
        let bit_len = self.message_len * 8;

        self.buffer.push(0x80);

        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }

        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        let final_blocks = std::mem::take(&mut self.buffer);
        for block in final_blocks.chunks_exact(64) {
            self.process_block_scalar(block.try_into().unwrap());
        }

        self.hash
    }
}

impl Default for CCSha256 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod padding_test {
    use super::*;

    #[test]
    fn md5test1() {
        let res = digest_msg_mine("");
        assert_eq!("d41d8cd98f00b204e9800998ecf8427e", res);
    }

    #[test]
    fn md5_test_a() {
        let res = digest_msg_mine("a");
        assert_eq!("0cc175b9c0f1b6a831c399e269772661", res);
    }

    #[test]
    fn md5_test_abc() {
        let res = digest_msg_mine("abc");
        assert_eq!("900150983cd24fb0d6963f7d28e17f72", res);
    }

    #[test]
    fn md5_test_message_digest() {
        let res = digest_msg_mine("message digest");
        assert_eq!("f96b697d7cb7938d525a2f31aaf161d0", res);
    }

    #[test]
    fn md5_test_message_random() {
        let res = digest_msg_mine("abcdefghijklmnopqrstuvwxyz");
        assert_eq!("c3fcd3d76192e4007dfb496cca67e13b", res);
    }
}
