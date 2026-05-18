use md5::{Digest, Md5};
use std::fs;
use std::io::{self, Read};

use std::env;
use std::process;

struct Config {
    b_flag: bool,
    c_flag: bool,
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

        if let Ok(digest) = self.digest() {
            format!("{}{}{}", digest, spacer, self.to_file_path())
            //dbg!(contents);
        } else {
            format!("Couldn't read file with path {}", self.to_file_path())
        }
    }

    fn digest(&self) -> Result<String, io::Error> {
        let content = self.read_file()?;
        Ok(digest_msg(&content))
    }

    fn validate_file(&self, config: &Config, error: &mut ErrorCount) -> String {
        let mut outs: Vec<String> = Vec::new();
        if let Ok(contents) = self.read_file() {
            for line in contents.lines() {
                let parts: Vec<&str> = line.split("  ").collect();
                if parts.len() >= 2 {
                    let first_option = parts[0];
                    let second_option = File::from(parts[1]);

                    let digest = second_option.digest();

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
                    // use first_option / second_option here
                } else {
                    let parts: Vec<&str> = line.split(" *").collect();
                    if parts.len() <= 2 {
                        error.inc_format += 1;
                    } else {
                        let first_option = parts[0];
                        let second_option = File::from(parts[1]);
                        let digest = second_option.digest();

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
    let mut inputs: Vec<File> = Vec::new();

    for arg in args {
        if arg == "-b" {
            b_flag = true;
        } else if arg == "-c" {
            c_flag = true
        } else {
            inputs.push(File::from(arg));
        }
    }

    (
        Config {
            b_flag: b_flag,
            c_flag: c_flag,
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
