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
//! Pstream is a utility in the Grey Squirrel ecosystem which provides a
//! convenient, cross-platform utility which streams process information on
//! STDOUT. It can be used to trivially demonstrate the use of Grey Squirrel
//! to detect the presence of a term within the process list or associated
//! environment variables attached to each process.
//! 
//! A buffer is maintained to ensure that only new processes are captured.
//!
//! Reminder: There are more efficient ways to stream some of these details
//! instead of polling, like the audit subsystem on Linux, if available.
//!
//! REMINDER: To see processes beyond the current user boundary, the process
//! must be privileged/executed as Root or with administrative privileges.
//!
//! USAGE EXAMPLE:
//!
//! Stream all process information to STDOUT - just run with the defaults:
//!
//! pstream
//!
//! Pipe into gsfind:
//!
//! pstream | gsfind --termfile <termfile>
//!
//! Dump all environmental variables across all processes on the system:
//!
//! AS ROOT or Administrator:
//!
//! pstream -e

extern crate lru;
use clap::Parser;
use env_logger::Env;
use log::debug;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::{thread, time};
use sysinfo::{PidExt, ProcessExt, System, SystemExt, UserExt};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct ProcessOutput {
    pid: u32,
    name: String,
    uid: String,        // String targets x86_64-pc-windows-gnu
    username: String,
    exe: String,
    cmd: String,
    env: Vec<String>,
    dedup: String,
}

#[derive(Parser)]
#[command(author, version, about = "Prepare terms for use with selector search", long_about = None)]
struct Args {
    /// Log level
    #[arg(long, default_value_t = String::from("info"))]
    loglevel: String,

    /// Include command line in output
    #[arg(long, short, default_value_t = true)]
    command: bool,

    /// Include environment in output
    #[arg(long, short, default_value_t = false)]
    environment: bool,

    /// Poll every miliseconds
    #[arg(long, short, default_value_t = 1000)]
    pollmillis: usize,

    /// LRU cache size for new process detection and de-duplication
    #[arg(long, short, default_value_t = 8192)]
    lrusize: usize,
}

fn poll_processes(
    mut sys: System,
    command: bool,
    environment: bool,
    lrusize: usize,
    millis: usize,
) {
    let mut cache = LruCache::new(
        NonZeroUsize::new(lrusize).expect("LRU cache size must be a positive integer"),
    );
    let pollmillis = time::Duration::from_millis(millis as u64);
    loop {
        for (ppid, process) in sys.processes() {
            let mut output = ProcessOutput {
                pid: ppid.as_u32(),
                ..Default::default()
            };
            //output.pid = pid.as_u32();
            if let Some(x) = process.exe().to_str() {
                output.exe = x.to_string();
            }
            output.name = process.name().to_string();
            if let Some(x) = process.user_id() {
                let uid = &x.clone();
                output.uid = uid.to_string();
                if let Some(y) = sys.get_user_by_id(x) {
                    output.username = y.name().to_string();
                }
            }
            if command {
                output.cmd = process.cmd().join(" ");
            }

            if environment {
                output.env = process.environ().to_vec();
            }
            let hash = format!(
                "{}//{}//{}//{}//{}",
                output.pid, output.uid, output.exe, output.name, output.cmd
            )
            .to_string();
            output.dedup = greysquirrel::prepare_selector(
                "pstream",
                &hash,
                &greysquirrel::SelectorAlgorithm::Mac,
            );
            match cache.get(&output.dedup) {
                None => {
                    cache.put(String::from(&output.dedup), ());
                    println!("{}", serde_json::to_string(&output).unwrap());
                }
                // Throw away the value, we aren't using it.
                Some(x) => debug!("Cache entry found for {}, {:?}", output.dedup, x),
            }
        }
        thread::sleep(pollmillis);
        sys.refresh_all();
    }
}

fn main() {
    let args = Args::parse();
    // Configure the logger
    env_logger::init_from_env(greysquirrel::get_log_env!(args.loglevel));

    debug!("Set open file limit to 0");

    debug!("Initializing system poller");
    let mut sys = System::new_all();
    sys.refresh_all();
    poll_processes(
        sys,
        args.command,
        args.environment,
        args.lrusize,
        args.pollmillis,
    );
}
