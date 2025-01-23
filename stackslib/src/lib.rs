// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![cfg_attr(test, allow(unused_variables, unused_assignments))]

#[macro_use(o, slog_log, slog_trace, slog_debug, slog_info, slog_warn, slog_error)]
extern crate slog;

#[macro_use]
extern crate serde_derive;

#[cfg(test)]
#[macro_use]
extern crate rstest;

#[cfg(test)]
#[macro_use]
extern crate rstest_reuse;

#[cfg(feature = "monitoring_prom")]
#[macro_use]
pub extern crate prometheus;

#[macro_use]
extern crate stacks_common;

#[macro_use]
pub extern crate clarity;

pub use stacks_common::{address, codec, types, util};

#[macro_use]
pub mod util_lib;

#[macro_use]
pub mod net;

pub extern crate libstackerdb;

#[macro_use]
pub mod chainstate;

pub mod burnchains;
pub mod clarity_cli;
/// A high level library for interacting with the Clarity vm
pub mod clarity_vm;
pub mod cli;
pub mod config;
pub mod core;
pub mod cost_estimates;
pub mod deps;
pub mod monitoring;

// set via _compile-time_ envars
const GIT_BRANCH: Option<&str> = option_env!("GIT_BRANCH");
const GIT_COMMIT: Option<&str> = option_env!("GIT_COMMIT");
const GIT_TREE_CLEAN: Option<&str> = option_env!("GIT_TREE_CLEAN");

#[cfg(debug_assertions)]
const BUILD_TYPE: &str = "debug";
#[cfg(not(debug_assertions))]
const BUILD_TYPE: &str = "release";

pub fn version_string(pkg_name: &str, pkg_version: &str) -> String {
    let git_branch = GIT_BRANCH.map(String::from).unwrap_or("".to_string());
    let git_commit = GIT_COMMIT.unwrap_or("");
    let git_tree_clean = GIT_TREE_CLEAN.unwrap_or("");

    format!(
        "{} {} ({}:{}{}, {} build, {} [{}])",
        pkg_name,
        pkg_version,
        &git_branch,
        git_commit,
        git_tree_clean,
        BUILD_TYPE,
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}
