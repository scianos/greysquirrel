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
//! Provides the ability to detect a set of strings or terms across a stream or
//! body of content, while keeping the search terms private barring a brute
//! force attack against the underlying HMAC implementation/algorithm. Common
//! use cases include the detection of secrets within a data stream without
//! exposing the secrets.
//!
//! Common use cases include:
//!  * Finding passwords accidentally leaked within process lists on a server
//!  or host, without having to expose the raw list of secrets to the host.
//!  This is useful in distributed systems where detection of the secrets must
//!  occur locally.
//!
//!  * Identifying potentially unwanted content without exposing the unwanted
//!  content.
//!
//! How does Grey Squirrel work?
//!
//! The technique used is straightforward:
//!
//!  * Terms are prepared by taking their length as a message, and then using
//!  the search term to "sign" the message.
//!
//!  * Given a list of terms, the search process can break a plaintext string
//!  into a corresponding set of partitions with the known lengths. Using the
//!  underlying known length and the content of the partition, a new search
//!  term can be calculated for every plaintext string partition.
//!
//!  * Search terms calculated from each plaintext string partition can be
//!  compared against the set of known terms. Terms that match indicate that
//!  the original content encoded within the search term appeared in the
//!  plaintext string that was searched.
//!
//! For example, to detect the string `Quei1lev0Nohro8ain` within a string of
//! text.
//!
//!  * Convert to a search term, which (unprefixed) becomes:
//!      18:886b31d36b521143ee87648a03debe31fa0240b2872e32b72d27262e3d511319
//!
//!  * Pass a plaintext string to the search function along with the above
//!  search term. Given the string:
//!      "Now is the time for all good `Quei1lev0Nohro8ain` to come to the aid
//!      of their country"
//!
//!  * The search function will detect the presence of the signal with the
//!  position the signal was found as a `SearchResult` structure:
//!
//!    [`SearchResult` { term: Term { mac: "886b31d36b521143ee87648a03debe31fa0240b2872e32b72d27262e3d511319",
//!                                 len: 18 }, part: `StringPartition` { part: `"Quei1lev0Nohro8ain"`,
//!                                                                    pos: 29,
//!                                                                    len: 18 } }]
//!
//! CONSIDERATIONS AND ATTACKS:
//!
//! The algorithm is designed for speed (once optimized re: UTF8 string
//! splitting, which is a current TODO) and eventually the ability to be
//! able to be embedded on common microcontrollers supported by rust's embedded
//! ecosystem. Note - short terms will be easily brute forced on modern
//! hardware by calculating every possible HMAC for a given length. Conversely,
//! the technique being used relies on the length being known to partition
//! strings. The content within the data stream itself is the signing key.
//!
//! This means it's possible to create both rainbow tables of every possible
//! signature with ease for short search terms, and they can also be brute
//! forced. Those considerations need to be taken into consideration by the
//! implementor. It is possible to seed Grey Squirrel with a prefix that will
//! be appended to every selector (a pepper), but this only protects against
//! pre-computation (the use of rainbow tables) and will not prevent trivial
//! brute force against short selectors.
//!
//! To increase computational complexity at the expense of detection speed,
//! it is possible to select an algorithm based on the needs of the operator:
//!
//!  * Mac: Raw HMAC-SHA256 without complexity. Very fast, suitable for
//!  embedded use cases. Don't use this algorithm with sensitive selectors,
//!  like passwords, unless the system running the workload is within the same
//!  trust boundary as the raw, plaintext being detected.
//!
//!  * Pbk: PBKDF2-based algorithm with 128 rounds against the known value to generate the
//!    final digest.
//!
//!  * Pbk1024: PBKDF2-based algorithm with 1024 rounds against the known value to generate
//!    the final digest.
//!
//!  * Pbk4096: PBKDF2-based algorithm with 4096 rounds against the known value to generate
//!    the final digest.
//!
//! Run with GS_LOG_LEVEL=debug for debugging output.
//! 

use data_encoding::HEXLOWER;
use lazy_static::lazy_static;
use log::debug;
use regex::Regex;
use ring::{digest, hmac, pbkdf2};
use serde::{Deserialize, Serialize};
use std::collections::BinaryHeap;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroU32;
use strum::{Display, EnumString};
use substring::Substring;

#[macro_use]
mod greysquirrel {
    #[macro_export]
    macro_rules! get_log_env {
        ($log_level:expr) => {{
            Env::default().filter_or("GS_LOG_LEVEL", $log_level)
        }};
    }
}

static PBKDF2_ALG: pbkdf2::Algorithm = pbkdf2::PBKDF2_HMAC_SHA256;
const PBKDF2_LEN: usize = digest::SHA256_OUTPUT_LEN;
const PBKDF2_ROUNDS: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(128) };
const PBKDF2_ROUNDS_1024: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(1024) };
const PBKDF2_ROUNDS_4096: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(4096) };
pub type Pbk = [u8; PBKDF2_LEN];

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Term {
    mac: String,
    len: usize,
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.len, self.mac)
    }
}

impl Term {
    /// Creates a new Term
    #[must_use]
    pub fn new(term: &str) -> Term {
        let mut termspec = term.split(':');
        Term {
            len: termspec
                .next()
                .expect("Missing LEN on term")
                .parse()
                .expect("LEN must be an integer"),
            mac: termspec
                .next()
                .expect("Missing MAC on term")
                .to_string()
                .to_lowercase(),
        }
    }

    #[must_use]
    pub fn to_key(&self) -> String {
        format!("{}:{}", self.len, self.mac)
    }

    #[must_use]
    pub fn from_string(prefix: &str, term: &str, algo: &SelectorAlgorithm) -> Term {
        let selector = prepare_selector(prefix, term, algo);
        debug!(
            "New selector created: {:?} from {:?},{:?},{:?}",
            selector, prefix, term, algo
        );
        Term::new(&selector)
    }

    #[must_use]
    pub fn mac(&self) -> &str {
        &self.mac
    }

    #[must_use]
    pub fn len(&self) -> &usize {
        &self.len
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct TermSet {
    terms: HashMap<String, Term>,
    lens: HashSet<usize>,
    maxlen: BinaryHeap<usize>,
}

impl TermSet {
    #[must_use]
    pub fn new() -> TermSet {
        TermSet {
            terms: HashMap::new(),
            lens: HashSet::with_capacity(1),
            maxlen: BinaryHeap::new(),
        }
    }

    /// Load a new term into the termset
    pub fn loadterm(&mut self, term: Term) {
        debug!("Load term {}", term);
        let termlen = term.len;
        self.lens.insert(termlen);
        self.terms.entry(term.to_string()).or_insert(term);
        self.maxlen.push(termlen);
    }

    /// Retrieve hashmap of all terms in the termset
    #[must_use]
    pub fn terms(&self) -> &HashMap<String, Term> {
        &self.terms
    }

    /// Retrieve the *unique* lengths of the terms across the termset
    #[must_use]
    pub fn lens(&self) -> Vec<usize> {
        self.lens.iter().copied().collect()
    }

    #[must_use]
    pub fn maxlen(&self) -> usize {
        let maxlen = self.maxlen.peek().unwrap_or(&0);
        *maxlen
    }
}

lazy_static! {
    pub static ref VALID_TERM: Regex = Regex::new("^[0-9]+:[A-Fa-f0-9]+$").unwrap();
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub term: Term,
    pub part: StringPartition,
}

impl SearchResult {
    /// Create a new `SearchResult`
    #[must_use]
    pub fn new(term: Term, part: StringPartition) -> SearchResult {
        SearchResult { term, part }
    }
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct StringPartition {
    pub part: String,
    pub pos: usize,
    pub len: usize,
}

impl StringPartition {
    /// Create a new string partition
    #[must_use]
    pub fn new(part: String, pos: usize, len: usize) -> StringPartition {
        StringPartition { part, pos, len }
    }

    #[must_use]
    /// Convert a string partition to a selector
    pub fn to_selector(&self, prefix: &str, algo: &SelectorAlgorithm) -> Term {
        Term::from_string(prefix, &self.part, algo)
    }
}

#[must_use]
pub fn search_partitions(
    prefix: &str,
    parts: &Vec<StringPartition>,
    terms: &TermSet,
    algo: &SelectorAlgorithm,
) -> Vec<SearchResult> {
    let mut results: Vec<SearchResult> = Vec::new();
    debug!("{:?}", terms);
    for part in parts {
        let selector = part.to_selector(prefix, algo);
        debug!("{:?} - {:?}", selector, part);
        if terms.terms().contains_key(&selector.to_key()) {
            results.push(SearchResult::new(selector, part.clone()));
        }
    }

    results
}

/// TODO: Optimize the string splitter
#[must_use]
pub fn build_term_strings(string: &str, termset: &TermSet) -> Vec<StringPartition> {
    let maxtermlen = termset.maxlen();
    let lens = termset.lens();
    let mut returnset: Vec<StringPartition> = Vec::new();
    debug!("Max term length is {}, lens are {:?}", maxtermlen, lens);
    let mut cp = 0;
    while cp < string.len() {
        for len in &lens {
            let substring = string.substring(cp, *len + cp);
            let cslice = StringPartition::new(String::from(substring), cp, substring.len());
            debug!("Substring: {:?}", cslice);
            returnset.push(cslice);
        }
        cp += 1;
    }
    returnset.dedup();
    returnset
}

#[derive(Hash, Eq, PartialEq, Debug, Clone, EnumString, Display)]
pub enum SelectorAlgorithm {
    #[strum(ascii_case_insensitive)]
    Mac,
    #[strum(ascii_case_insensitive)]
    Pbk,
    #[strum(ascii_case_insensitive)]
    Pbk1024,
    #[strum(ascii_case_insensitive)]
    Pbk4096,
}

fn selector_mac(mac_msg: &str, final_selector: &str) -> String {
    debug!("SELECTOR_MAC: {:?}", final_selector);
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, final_selector.as_ref());
    let mac_sign = hmac::sign(&mac_key, mac_msg.as_bytes());
    let mac_hex = HEXLOWER.encode(mac_sign.as_ref());
    let prepared_selector = format!("{mac_msg}:{mac_hex}");
    prepared_selector
}

fn selector_pbk_backend(mac_msg: &str, final_selector: &str, rounds: NonZeroU32) -> String {
    let salttext = selector_mac(mac_msg, final_selector);
    let mut salt = Vec::with_capacity(salttext.len());
    salt.extend(salttext.as_bytes());
    let selbytes = final_selector.as_bytes();
    let mut buffer = [0u8; PBKDF2_LEN];
    pbkdf2::derive(PBKDF2_ALG, rounds, &salt, selbytes, &mut buffer);
    let mac_hex = HEXLOWER.encode(buffer.as_ref());
    let prepared_selector = format!("{mac_msg}:{mac_hex}");
    prepared_selector
}

fn selector_pbk(mac_msg: &str, final_selector: &str) -> String {
    selector_pbk_backend(mac_msg, final_selector, PBKDF2_ROUNDS)
}

fn selector_pbk1024(mac_msg: &str, final_selector: &str) -> String {
    selector_pbk_backend(mac_msg, final_selector, PBKDF2_ROUNDS_1024)
}

fn selector_pbk4096(mac_msg: &str, final_selector: &str) -> String {
    selector_pbk_backend(mac_msg, final_selector, PBKDF2_ROUNDS_4096)
}

#[must_use]
pub fn prepare_selector(prefix: &str, selector: &str, algo: &SelectorAlgorithm) -> String {
    let mut final_selector: String = prefix.to_owned();
    final_selector.push_str(selector);
    let mac_msg = selector.len().to_string();
    match algo {
        SelectorAlgorithm::Mac => selector_mac(&mac_msg, &final_selector),
        SelectorAlgorithm::Pbk => selector_pbk(&mac_msg, &final_selector),
        SelectorAlgorithm::Pbk1024 => selector_pbk1024(&mac_msg, &final_selector),
        SelectorAlgorithm::Pbk4096 => selector_pbk4096(&mac_msg, &final_selector),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_logger::Env;

    #[test]
    fn termset_impl() {
        let mut expected_result = TermSet::new();
        expected_result.loadterm(Term::new(
            "3:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0",
        )); // had
        expected_result.loadterm(Term::new(
            "6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76",
        )); // little
        assert!(
            expected_result.maxlen.peek().unwrap_or(&0) == &6,
            "Maxlen matches expected value"
        );
        assert!(
            vec![3, 6]
                .iter()
                .all(|item| Vec::from_iter(&expected_result.lens).contains(&item)),
            "Lens match expected results"
        );

        assert!(
            vec![
                "3:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0",
                "6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76"
            ]
            .iter()
            .all(|&item| expected_result.terms().contains_key(item)),
            "Terms() return expected term keys"
        );

        assert!(
            vec![3, 6]
                .iter()
                .all(|item| Vec::from_iter(&expected_result.lens()).contains(&item)),
            "Lens match expected results"
        );
        assert_eq!(
            expected_result.maxlen(),
            6,
            "Maxlen() returns expected value"
        );
    }

    #[test]
    fn valid_term_regex() {
        let should_match = VALID_TERM
            .is_match("6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76");
        let should_not_match = VALID_TERM
            .is_match("blar:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76");
        assert_eq!(should_match, true, "Regex should match valid term");
        assert_eq!(
            should_not_match, false,
            "Regex should not match invalid term"
        );
    }

    #[test]
    fn default_termset() {
        let default_ts: TermSet = Default::default();
        assert_eq!(
            default_ts.maxlen(),
            0,
            "Default termset is created successfully"
        );
    }

    #[test]
    fn string_partition_impl() {
        let sp: StringPartition = StringPartition::new("a".to_string(), 0, 1);
    }

    #[test]
    fn string_builder_and_search() {
        let mut termset1 = TermSet::new();
        termset1.loadterm(Term::new(
            "3:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0",
        )); // had
        termset1.loadterm(Term::new(
            "6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76",
        )); // little
        let mut termset2 = TermSet::new();
        termset2.loadterm(Term::new(
            "6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76",
        )); // little
        let empty_termset = TermSet::new();
        let input = "Mary had a little lamb.";
        let builder = build_term_strings(input, &termset1);
        let result = search_partitions("", &builder, &termset1, &SelectorAlgorithm::Pbk);
        let result2 = search_partitions("", &builder, &termset2, &SelectorAlgorithm::Pbk);
        let result_empty = search_partitions("", &builder, &empty_termset, &SelectorAlgorithm::Pbk);
        let result_1_terms = result.iter().map(|x| x.term.to_key()).collect::<Vec<_>>();
        let result_2_terms = result2.iter().map(|x| x.term.to_key()).collect::<Vec<_>>();
        let result_empty_terms = result_empty
            .iter()
            .map(|x| x.term.to_key())
            .collect::<Vec<_>>();
        let result_1_expect = vec![
            "6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76".to_string(),
            "3:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0".to_string(),
        ];
        let result_2_expect =
            vec!["6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76".to_string()];
        assert_eq!(result_1_terms.len(), 2, "Expected length on result 1 terms");
        assert_eq!(result_2_terms.len(), 1, "Expected length on result 2 terms");
        assert_eq!(
            empty_termset.terms.len(),
            0,
            "Expected length on empty termset"
        );
        assert!(
            result_1_expect
                .iter()
                .all(|item| result_1_terms.contains(&item)),
            "Match expected search answer on results 1"
        );
        assert!(
            result_2_expect
                .iter()
                .all(|item| result_2_terms.contains(&item)),
            "Match expected search answer on results 2"
        );
        assert!(
            vec!["".to_string(); 0]
                .iter()
                .all(|item| result_empty_terms.contains(&item)),
            "Match expected search answer on results empty"
        );
    }

    #[test]
    fn build_term_string() {
        let mut termset1 = TermSet::new();
        termset1.loadterm(Term::new(
            "3:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0",
        )); // had
        termset1.loadterm(Term::new(
            "6:07972a992a82ee64c8ad2f113abbd8a1b2e61c833a735ab9db2d0637f64f7f76",
        )); // little
        let expected_result = vec![
            "Tes//0//3",
            "Test t//0//6",
            "est//1//3",
            "est te//1//6",
            "st //2//3",
            "st tes//2//6",
            "t t//3//3",
            "t test//3//6",
            " te//4//3",
            " test//4//5",
            "tes//5//3",
            "test//5//4",
            "est//6//3",
            "st//7//2",
            "t//8//1",
        ];
        let builder = build_term_strings("Test test", &termset1);
        let concat_results = builder
            .iter()
            .map(|x| format!("{}//{}//{}", x.part, x.pos, x.len))
            .collect::<Vec<_>>();
        assert!(
            expected_result
                .iter()
                .all(|item| concat_results.contains(&item.to_string())),
            "Match expected string builder result based on given termset"
        );
    }

    #[test]
    fn get_log_env_macro() {
        let log_env = get_log_env!("GS_LOG_LEVEL");
        assert!(
            format!("{:?}", log_env).contains("GS_LOG_LEVEL"),
            "Confirm log initialization macro performs function"
        );
    }

    #[test]
    fn stringpartition_impl() {
        let part = StringPartition::new("had".to_string(), 6, 3);
        let sel = part.to_selector("", &SelectorAlgorithm::Pbk);
        let sel_cmp =
            Term::new("3:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0");
        let sel_bad =
            Term::new("4:4025a189f5be0738cf351e7ed8e40d29600eef970b621858a85a496c2201fff0");
        assert_eq!(part.part, "had", "Part matches");
        assert_eq!(part.pos, 6, "Pos matches");
        assert_eq!(part.len, 3, "Part matches");
        assert!(sel == sel_cmp, "to_selector() matches");
        assert!(sel != sel_bad, "to_selector() matches");
    }

    #[test]
    fn term_impl() {
        let term = Term::new("23:3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8");
        assert_eq!(
            "23:3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8",
            term.to_string(),
            "Term and display match"
        );
        assert_eq!(23, term.len, "Term length match");
        assert_eq!(
            "3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8", term.mac,
            "Term MAC match"
        );
        assert_eq!(
            term.to_key(),
            "23:3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8",
            "Check to_key()"
        );
        assert_eq!(
            term.mac(),
            "3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8",
            "Check mac()"
        );
        assert_eq!(term.len(), &23, "Check len()");
    }

    #[test]
    fn prepare_selector_algos() {
        let test_text = "Mary had a little lamb.";

        assert_eq!(
            "23:3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8",
            prepare_selector("", &test_text, &SelectorAlgorithm::Mac),
            "Algorithm Mac"
        );

        assert_eq!(
            "23:6551b16700dd5424f8fc17bd5e62bb3b1ec1757ac9b46ae50afd485005d57df9",
            prepare_selector("", &test_text, &SelectorAlgorithm::Pbk),
            "Algorithm Pbk"
        );
        assert_eq!(
            "23:3d5f2bf0fbd89e9978ac3541d3f4cd06674f861270dd61ae7e51db70e443dd48",
            prepare_selector("", &test_text, &SelectorAlgorithm::Pbk1024),
            "Algorithm Pbk1024"
        );
        assert_eq!(
            "23:85a7cc9a9382276905ebc1f76254c580389775cfb676e1462d723190f32ba9c6",
            prepare_selector("", &test_text, &SelectorAlgorithm::Pbk4096),
            "Algorithm Pbk4096"
        );
    }

    #[test]
    fn prepare_selector_test() {
        let english_selector =
            "23:3119e8adf4079c9fef3d03a6486921167c23b8005d652bfb65c227151c5cffb8";
        let english_term = String::from("Mary had a little lamb.");
        assert_eq!(
            english_selector,
            prepare_selector("", &english_term, &SelectorAlgorithm::Mac),
            "Prepare 1 - English"
        );
        let spanish_selector =
            "27:8fde40e4ab1380ac9e57d6a4b8c7cc8b14caed700fb2698083b97bcf175151cc";
        let spanish_term = String::from("María tenía un corderito.");
        assert_eq!(
            spanish_selector,
            prepare_selector("", &spanish_term, &SelectorAlgorithm::Mac),
            "Prepare 2 - Spanish"
        );
        let chinese_simplified_selector =
            "21:7e2295fd2a376b7ffabe310da8cf3eb1c6b9a4949eb13010ab40872ff8c28747";
        let chinese_simplified_term = String::from("玛丽有只小羊羔");
        assert_eq!(
            chinese_simplified_selector,
            prepare_selector("", &chinese_simplified_term, &SelectorAlgorithm::Mac),
            "Prepare 3 - Chinese Simplified"
        );
        let chinese_simplified_p_selector =
            "32:cc393eea3f96808679d3e16f88d2cf46bac48ad2c39d4cb891e9267ca9bdcc76";
        let chinese_simplified_p_term = String::from("Mǎlì yǒu zhǐ xiǎo yánggāo");
        assert_eq!(
            chinese_simplified_p_selector,
            prepare_selector("", &chinese_simplified_p_term, &SelectorAlgorithm::Mac),
            "Prepare 4 - Chinese Simplified P"
        );
        assert_eq!(
            "0:9979e4c3ee19965f9ecc6dca6b3954b10c18c1bfa105c512cc3ae58be85db71c",
            prepare_selector("", "", &SelectorAlgorithm::Mac),
            "Empty Selector"
        );
        assert_eq!(
            "11:75bd679cb5b9783468f122de9bcabda3f55258f7c3b767df39674b36f3a66499",
            prepare_selector("SQUIRReL", "Hello World", &SelectorAlgorithm::Mac),
            "Selector with Global Prefix"
        );
    }
}
