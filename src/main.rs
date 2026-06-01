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
    out.iter().map(|byte| format!("{:02x}", byte)).collect()
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

struct CCSha256 {
    hash: [u32; 8],
    table: [u32; 64],
    state: [u32; 8],
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
            state: INITIAL,
            buffer: Vec::new(),
            message_len: 0,
        }
    }

    fn reset_state(&mut self) {
        self.state = self.hash;
    }

    fn process_block(&mut self, content: &[u8; 64]) {
        let mut buffer_msg = [0u32; 16];
        let mut wt = [0u32; 64];

        for (i, word_bytes) in content.chunks_exact(4).enumerate() {
            buffer_msg[i] =
                u32::from_be_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        for t in 0..16 {
            wt[t] = buffer_msg[t]
        }
        for t in 16..64 {
            wt[t] = u32::ssig1(wt[t - 2])
                .wrapping_add(wt[t - 7])
                .wrapping_add(u32::ssig0(wt[t - 15]))
                .wrapping_add(wt[t - 16]);
        }

        self.reset_state();

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

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
        self.state = [a, b, c, d, e, f, g, h];
        self.update_hash();
    }

    fn update_hash(&mut self) {
        self.hash = std::array::from_fn(|i| self.hash[i].wrapping_add(self.state[i]));
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

    fn finalize(mut self) -> [u32; 8] {
        let bit_len = self.message_len * 8;

        self.buffer.push(0x80);

        while self.buffer.len() % 64 != 56 {
            self.buffer.push(0);
        }

        self.buffer.extend_from_slice(&bit_len.to_be_bytes());

        let final_blocks = std::mem::take(&mut self.buffer);
        for block in final_blocks.chunks_exact(64) {
            self.process_block(block.try_into().unwrap());
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
