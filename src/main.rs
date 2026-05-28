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
    let mut inputs: Vec<File> = Vec::new();

    for arg in args {
        if arg == "-b" {
            b_flag = true;
        } else if arg == "-c" {
            c_flag = true
        } else if arg == "--quiet" {
            quiet_flag = true
        } else if arg == "--mine" {
            mine = true
        } else {
            inputs.push(File::from(arg));
        }
    }

    (
        Config {
            b_flag: b_flag,
            c_flag: c_flag,
            quiet_flag: quiet_flag,
            mine: mine,
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

fn digest_msg(contents: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(contents);
    let hash: [u8; 16] = hasher.finalize().into();
    let hash_hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();
    hash_hex
}

fn digest_msg_mine(contents: &[u8]) -> String {
    let out = rounds(contents);
    let hash_hex: String = out
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .map(|byte| format!("{:02x}", byte))
        .collect();
    hash_hex
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

//fn padding_content(mut bytes: Vec<u8>) -> Vec<u8> {
//    let bit_len = (bytes.len() as u64) * 8;
//
//    bytes.push(0x80);
//
//    while bytes.len() % 64 != 56 {
//        bytes.push(0x0);
//    }
//
//    bytes.extend_from_slice(&bit_len.to_le_bytes());
//
//    bytes
//}

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
        }
    }
    fn padding_content(&self, mut bytes: Vec<u8>) -> Vec<u8> {
        let bit_len = (bytes.len() as u64) * 8;

        bytes.push(0x80);

        while bytes.len() % 64 != 56 {
            bytes.push(0x0);
        }

        bytes.extend_from_slice(&bit_len.to_le_bytes());

        bytes
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
        self.state.values.rotate_right(1);
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
}

fn rounds(content: &[u8]) -> [u32; 4] {
    let content = content.to_vec();

    let mut ccmd5 = CCMd5::new();

    let bytes = ccmd5.padding_content(content);
    let mut buffer_msg = [0u32; 16];

    for chunk in bytes.chunks_exact(64) {
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            buffer_msg[i] =
                u32::from_le_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        ccmd5.reset_state();

        // MD5 uses K[0..63] in order across all 4 rounds.

        // Round 1
        let k_values = make_k_index(0, 1);
        let s: [u32; 4] = [7, 12, 17, 22];

        ccmd5.round(&buffer_msg, k_values, s, &Fm);

        // Round 2
        let k_values = make_k_index(1, 5);
        let s: [u32; 4] = [5, 9, 14, 20];

        ccmd5.round(&buffer_msg, k_values, s, &Gm);

        // Round 3
        let k_values = make_k_index(5, 3);
        let s: [u32; 4] = [4, 11, 16, 23];

        ccmd5.round(&buffer_msg, k_values, s, &Hm);

        // Round 4
        let k_values = make_k_index(0, 7);
        let s: [u32; 4] = [6, 10, 15, 21];

        ccmd5.round(&buffer_msg, k_values, s, &Im);

        ccmd5.update_hash();
    }

    ccmd5.hash
}

struct CCMd5 {
    hash: [u32; 4],
    table: [u32; 64],
    state: State,
}
struct State {
    values: [u32; 4],
    i: usize,
}

fn Fm(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b & d)
}

fn Gm(b: u32, c: u32, d: u32) -> u32 {
    (b & d) | (c & !d)
}

fn Hm(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn Im(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b | (!d))
}

#[cfg(test)]
mod padding_test {
    use super::*;

    #[test]
    fn pads_empty_string() {
        let padded = padding_content(Vec::from("".as_bytes()));
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[0], 0x80);
        assert_eq!(&padded[1..56], [0u8; 55]);
        assert_eq!(&padded[56..64], &0u64.to_le_bytes());
    }

    #[test]
    fn pads_single_a() {
        let padded = padding_content(Vec::from("a".as_bytes()));
        assert_eq!(padded.len(), 64);
        assert_eq!(padded[0], 0x61);
        assert_eq!(padded[1], 0x80);
        assert_eq!(&padded[2..56], [0u8; 54]);
        assert_eq!(&padded[56..64], &8u64.to_le_bytes());
    }

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
