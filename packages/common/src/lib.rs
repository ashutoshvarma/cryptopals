pub use anyhow::Result;
pub use anyhow;
pub use thiserror;

pub trait CanRun {
    const NAME: &'static str;
    const SET: usize;
    const PROBLEM: usize;

    type Output;

    fn run() -> Result<Self::Output>;
    fn check(v: Self::Output, expected: Self::Output) -> Result<()>;
}
