//! (C) Copyright 2022 Stuart Cianos. All Rights Reserved.
//! This program is free software; you can redistribute it and/or
//! modify it under the terms of the GNU General Public License
//! as published by the Free Software Foundation; either version 2
//! of the License, or (at your option) any later version.
//! 
//! This program is distributed in the hope that it will be useful,
//! but WITHOUT ANY WARRANTY; without even the implied warranty of
//! MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//! GNU General Public License for more details.
//! 
//! You should have received a copy of the GNU General Public License
//! along with this program; if not, write to the Free Software
//! Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//!
//! SPDX-License-Identifier: GPL-2.0
//!
//! Grey Squirrel:
//! A library for covertly detecting signals (strings/bytes), without revealing
//! the search term until detected.
//!
//! Gstermp is a utility which prepares terms. Plain text terms are provided
//! one to a line on STDIN, with the resulting transformed selector output to
//! STDOUT.
use clap::Parser;
use env_logger::Env;
use log::{debug, info};
use std::io;
use std::str::FromStr;
use strum::{Display, EnumString};

#[derive(Parser)]
#[command(author, version, about = "Prepare terms for use with selector search", long_about = None)]
struct Args {
    /// Log level
    #[arg(long, default_value_t = String::from("info"))]
    loglevel: String,

    /// Global prefix
    #[arg(long, short, default_value_t = String::from(""))]
    globalprefix: String,

    /// Algorithm
    #[arg(long, short, value_enum, default_value_t =SelectorAlgorithm::Pbk, required = false)]
    algorithm: SelectorAlgorithm,
}

#[derive(clap::ValueEnum, Clone, Debug, EnumString, Display)]
#[clap(rename_all = "lower_case")]
enum SelectorAlgorithm {
    #[strum(ascii_case_insensitive)]
    Pbk,
    #[strum(ascii_case_insensitive)]
    Pbk1024,
    #[strum(ascii_case_insensitive)]
    Pbk4096,
    #[strum(ascii_case_insensitive)]
    Mac,
}

fn main() {
    // Get any command line arguments passed
    let args = Args::parse();
    let algorithm = greysquirrel::SelectorAlgorithm::from_str(&args.algorithm.to_string()).unwrap();
    // Configure the logger
    env_logger::init_from_env(greysquirrel::get_log_env!(args.loglevel));
    info!("Prepare terms, send EOF (CTRL-D) to finish");
    let mut term_counter = 0;
    let stdin = io::stdin();
    let mut buffer = String::new();
    while stdin.read_line(&mut buffer).is_ok() {
        if buffer.is_empty() {
            debug!("EOF received");
            break;
        }
        let trimmed_buffer = buffer.trim();
        println!(
            "{}",
            greysquirrel::prepare_selector(&args.globalprefix, trimmed_buffer, &algorithm)
        );
        term_counter += 1;
        buffer.clear();
    }
    info!("Prepared {term_counter} terms");
}
