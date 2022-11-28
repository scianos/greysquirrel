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
//! Gsfind is a utility which searches input on STDIN and reports findings on
//! STDOUT.
//!
//! Usage: gsfind [OPTIONS]
//!
//! Options:
//!       --loglevel <LOGLEVEL>          Log level [default: info]
//!   -g, --globalprefix <GLOBALPREFIX>  Global prefix [default: ]
//!   -t, --termfile <TERMFILE>          Read terms from file (one per line)
//!       --termstdin                    Read terms on stdin, send single period (".") to start detector
//!   -T, --terms <TERMS>                Pre-load terms via argument
//!   -n, --notification <NOTIFICATION>  Notification Type to log [default: selector] [possible values: selector, ping, detail]
//!   -a, --algorithm <ALGORITHM>        Algorithm [default: pbk] [possible values: pbk, pbk1024, pbk4096, mac]
//!   -S, --suppress-stdout              Suppress stdout on match; only output to stderr logger
//!   -h, --help                         Print help information
//!   -V, --version                      Print version information
//!
//! USAGE EXAMPLE:
//!
//! Find the secret "ThisIsASpecialTerm" in a stream of data.
//!
//! 1. Prepare the term(s) with gstermp.
//!
//! echo -n "ThisIsASpecialTerm" | gstermp > test.trm
//!
//! 2. Use the resultant term file to scan input.
//!
//! Given the text "Mary had a ThisIsASpecialTerm lamb.":
//!
//! echo "Mary had a ThisIsASpecialTerm lamb." | target/debug/gsfind --termfile test.trm
//!
//! Returns a positive match:
//! [{"mac":"5234796ed7471167ef453caeed514c370cbca1883ab9a83b4dc97595f4aba685","len":18}]

use clap::Parser;
use env_logger::Env;
use log::{debug, error, info, warn};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::str::FromStr;
use strum::{Display, EnumString};

#[derive(Parser)]
#[command(author, version, about = "Find selectors on stdin, report on stdout", long_about = None)]
struct Args {
    /// Log level
    #[arg(long, default_value_t = String::from("info"))]
    loglevel: String,

    /// Global prefix
    #[arg(long, short, default_value_t = String::from(""))]
    globalprefix: String,

    /// Read terms from file (one per line)
    #[arg(long, short, required = false)]
    termfile: Option<String>,

    /// Read terms on stdin, send single period (".") to start detector
    #[arg(long, default_value_t = false)]
    termstdin: bool,

    /// Pre-load terms via argument
    #[arg(long, short = 'T', required = false)]
    terms: Option<Vec<String>>,

    /// Notification Type to log
    #[arg(long, short = 'n', value_enum, default_value_t = NotificationTypes::Selector, required = false)]
    notification: NotificationTypes,

    /// Algorithm
    #[arg(long, short, value_enum, default_value_t =SelectorAlgorithm::Pbk, required = false)]
    algorithm: SelectorAlgorithm,

    /// Suppress stdout on match; only output to stderr logger
    #[arg(long = "suppress-stdout", short = 'S', default_value_t = false)]
    suppress: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
#[clap(rename_all = "lower_case")]
enum NotificationTypes {
    Selector,
    Ping,
    Detail,
}

#[derive(clap::ValueEnum, Clone, Debug, EnumString, Display)]
#[clap(rename_all = "lower_case")]
enum SelectorAlgorithm {
    Pbk,
    Pbk1024,
    Pbk4096,
    Mac,
}

enum OperatingState {
    ReadTerms,
    ScanText,
}

fn file_iterate_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn read_from_termfile(termfile: &str, termset: &mut greysquirrel::TermSet) {
    let mut termcount = 0;
    info!("Reading from termfile [{termfile}]");
    if let Ok(termlines) = file_iterate_lines(termfile) {
        debug!("Opened termfile");
        for rline in termlines {
            let trimmed_line = rline.as_deref().unwrap().trim();
            debug!("Read from file {trimmed_line}");
            if greysquirrel::VALID_TERM.is_match(trimmed_line) {
                let newterm = greysquirrel::Term::new(trimmed_line);
                termset.loadterm(newterm);
                termcount += 1;
            } else {
                error!("Invalid term \"{trimmed_line}\". Valid format is <LEN>:<MAC>");
            }
        }
        info!("Loaded {termcount} terms");
    }
}

fn main() {
    // Get any command line arguments passed
    let args = Args::parse();
    let algorithm = greysquirrel::SelectorAlgorithm::from_str(&args.algorithm.to_string()).unwrap();
    // Configure the logger
    env_logger::init_from_env(greysquirrel::get_log_env!(args.loglevel));
    let stdin = io::stdin();
    let mut buffer = String::new();
    let mut state = OperatingState::ScanText;
    let mut termset: greysquirrel::TermSet = greysquirrel::TermSet::new();
    let prefix = args.globalprefix;

    if args.termstdin {
        state = OperatingState::ReadTerms;
        warn!("Reading terms from STDIN. When done, enter a single period (.)");
    }

    if args.termfile.is_some() {
        let termfile = args.termfile.unwrap();
        read_from_termfile(&termfile, &mut termset);
    }

    while stdin.read_line(&mut buffer).is_ok() {
        let trimmed_buffer = buffer.trim();
        if buffer.is_empty() {
            info!("EOF received");
            break;
        }
        match state {
            OperatingState::ScanText => {
                let builder = greysquirrel::build_term_strings(buffer.trim(), &termset);
                let results =
                    greysquirrel::search_partitions(&prefix, &builder, &termset, &algorithm);
                debug!("Term Builder Result: {:?}", builder);
                debug!("Search Result: {:?}", results);
                if !results.is_empty() {
                    match args.notification {
                        NotificationTypes::Selector => {
                            let returnterms = results.iter().map(|x| &x.term).collect::<Vec<_>>();
                            let returnout = serde_json::to_string(&returnterms).unwrap();
                            if !args.suppress {
                                println!("{}", &returnout);
                            }
                            info!("<MATCH> {}", returnout);
                        }
                        NotificationTypes::Ping => {
                            if !args.suppress {
                                println!("[]");
                            }
                            info!("<MATCH> []");
                        }
                        NotificationTypes::Detail => {
                            let returnout = serde_json::to_string(&results).unwrap();
                            if !args.suppress {
                                println!("{}", &returnout);
                            }
                            info!("<MATCH> {}", returnout);
                        }
                    }
                }
            }
            OperatingState::ReadTerms => {
                if buffer.trim() == "." {
                    state = OperatingState::ScanText;
                    warn!("Exiting term mode, entering scan mode");
                } else if greysquirrel::VALID_TERM.is_match(trimmed_buffer) {
                    let newterm = greysquirrel::Term::new(trimmed_buffer);
                    termset.loadterm(newterm);
                } else {
                    error!("Invalid term format. Valid format is <LEN>:<MAC>");
                }
            }
        }
        buffer.clear();
    }
}
