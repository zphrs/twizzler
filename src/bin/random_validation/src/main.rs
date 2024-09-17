extern crate twizzler_abi;
use std::mem::MaybeUninit;
mod diehardest;

use getrandom::getrandom;

use crate::diehardest::{analysis::Report, crush};

#[derive(Clone)]
struct Rng;

impl diehardest::Random for Rng {
    fn get_random(&mut self) -> u64 {
        let mut into = [0u8; 8];
        getrandom(&mut into);
        u64::from_ne_bytes(into)
    }
}
// TODO: instead of running these very basic tests,
// find a way to stream data out of twizzler and onto the
// computer. Currently not a
fn main() {
    let mut into: [u8; 32] = Default::default();
    let report = Report::new(Rng);
    let score = report.get_score();

    println!(
        "score: {}/{}, breakdown: {:?}",
        score.total(),
        1020,
        report.get_score()
    );
}
