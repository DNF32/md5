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

    fn read_file(&self) -> Result<String, io::Error> {
        match self {
            Self::StdIn => {
                let mut buffer = String::new();
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
        if let Ok(contents) = self.read_file() {
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

fn digest_msg(contents: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(contents.as_bytes());
    let hash: [u8; 16] = hasher.finalize().into();
    let hash_hex: String = hash.iter().map(|byte| format!("{:02x}", byte)).collect();
    hash_hex
}

fn digest_msg_mine(contents: &str) -> String {
    let out = rounds(Vec::from(contents.as_bytes()));
    let hash_hex: String = out.iter().map(|byte| format!("{:02x}", byte)).collect();
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

fn padding_content(mut bytes: Vec<u8>) -> Vec<u8> {
    let bit_len = (bytes.len() as u64) * 8;

    bytes.push(0x80);

    while bytes.len() % 64 != 56 {
        bytes.push(0x0);
    }

    bytes.extend_from_slice(&bit_len.to_le_bytes());

    bytes
}

fn rounds(content: Vec<u8>) -> Vec<u8> {
    let mut A: u32 = 0x67452301;
    let mut B: u32 = 0xefcdab89;
    let mut C: u32 = 0x98badcfe;
    let mut D: u32 = 0x10325476;

    let table = make_table::<64>();

    let bytes = padding_content(content);
    let mut buffer_msg = [0u32; 16];

    for chunk in bytes.chunks_exact(64) {
        for (i, word_bytes) in chunk.chunks_exact(4).enumerate() {
            buffer_msg[i] =
                u32::from_le_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        let mut a = A;
        let mut b = B;
        let mut c = C;
        let mut d = D;

        // MD5 uses K[0..63] in order across all 4 rounds.
        let mut step: usize = 0;

        // Round 1
        let k_values = make_k_index(0, 1);
        let s: [u32; 4] = [7, 12, 17, 22];
        for i in 0..4 {
            a = iter(
                a,
                b,
                c,
                d,
                k_values[i * 4],
                s[0],
                step,
                Fm,
                buffer_msg,
                table,
            );
            step += 1;
            d = iter(
                d,
                a,
                b,
                c,
                k_values[i * 4 + 1],
                s[1],
                step,
                Fm,
                buffer_msg,
                table,
            );
            step += 1;
            c = iter(
                c,
                d,
                a,
                b,
                k_values[i * 4 + 2],
                s[2],
                step,
                Fm,
                buffer_msg,
                table,
            );
            step += 1;
            b = iter(
                b,
                c,
                d,
                a,
                k_values[i * 4 + 3],
                s[3],
                step,
                Fm,
                buffer_msg,
                table,
            );
            step += 1;
        }

        // Round 2
        let k_values = make_k_index(1, 5);
        let s: [u32; 4] = [5, 9, 14, 20];
        for i in 0..4 {
            a = iter(
                a,
                b,
                c,
                d,
                k_values[i * 4],
                s[0],
                step,
                Gm,
                buffer_msg,
                table,
            );
            step += 1;
            d = iter(
                d,
                a,
                b,
                c,
                k_values[i * 4 + 1],
                s[1],
                step,
                Gm,
                buffer_msg,
                table,
            );
            step += 1;
            c = iter(
                c,
                d,
                a,
                b,
                k_values[i * 4 + 2],
                s[2],
                step,
                Gm,
                buffer_msg,
                table,
            );
            step += 1;
            b = iter(
                b,
                c,
                d,
                a,
                k_values[i * 4 + 3],
                s[3],
                step,
                Gm,
                buffer_msg,
                table,
            );
            step += 1;
        }

        // Round 3
        let k_values = make_k_index(5, 3);
        let s: [u32; 4] = [4, 11, 16, 23];
        for i in 0..4 {
            a = iter(
                a,
                b,
                c,
                d,
                k_values[i * 4],
                s[0],
                step,
                Hm,
                buffer_msg,
                table,
            );
            step += 1;
            d = iter(
                d,
                a,
                b,
                c,
                k_values[i * 4 + 1],
                s[1],
                step,
                Hm,
                buffer_msg,
                table,
            );
            step += 1;
            c = iter(
                c,
                d,
                a,
                b,
                k_values[i * 4 + 2],
                s[2],
                step,
                Hm,
                buffer_msg,
                table,
            );
            step += 1;
            b = iter(
                b,
                c,
                d,
                a,
                k_values[i * 4 + 3],
                s[3],
                step,
                Hm,
                buffer_msg,
                table,
            );
            step += 1;
        }

        // Round 4
        let k_values = make_k_index(0, 7);
        let s: [u32; 4] = [6, 10, 15, 21];
        for i in 0..4 {
            a = iter(
                a,
                b,
                c,
                d,
                k_values[i * 4],
                s[0],
                step,
                Im,
                buffer_msg,
                table,
            );
            step += 1;
            d = iter(
                d,
                a,
                b,
                c,
                k_values[i * 4 + 1],
                s[1],
                step,
                Im,
                buffer_msg,
                table,
            );
            step += 1;
            c = iter(
                c,
                d,
                a,
                b,
                k_values[i * 4 + 2],
                s[2],
                step,
                Im,
                buffer_msg,
                table,
            );
            step += 1;
            b = iter(
                b,
                c,
                d,
                a,
                k_values[i * 4 + 3],
                s[3],
                step,
                Im,
                buffer_msg,
                table,
            );
            step += 1;
        }

        A = A.wrapping_add(a);
        B = B.wrapping_add(b);
        C = C.wrapping_add(c);
        D = D.wrapping_add(d);
    }

    let mut digest: Vec<u8> = Vec::new();
    digest.extend(A.to_le_bytes());
    digest.extend(B.to_le_bytes());
    digest.extend(C.to_le_bytes());
    digest.extend(D.to_le_bytes());
    digest
}

fn iter<F>(
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    k: usize,
    s: u32,
    i: usize,
    f: F,
    x: [u32; 16],
    table: [u32; 64],
) -> u32
where
    F: Fn(u32, u32, u32) -> u32,
{
    //b + ((a + f(b, c, d) + x[k] + table[i]) << s)
    let f_res = f(b, c, d);

    let sum = a
        .wrapping_add(f_res)
        .wrapping_add(x[k])
        .wrapping_add(table[i]);

    let rot = sum.rotate_left(s);

    b.wrapping_add(rot)
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
