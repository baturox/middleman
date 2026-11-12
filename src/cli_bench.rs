use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;
pub async fn bench_cmd(_c: &Path, _m: &str, _t: usize, _k: bool, _y: bool) -> Result<ExitCode> {
    Ok(ExitCode::SUCCESS)
}
