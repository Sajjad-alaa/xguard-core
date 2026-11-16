use std::fs;

use utoipa::OpenApi;
use xguard_core::openapi::ApiDoc;

fn main() -> anyhow::Result<()> {
    let mut spec = ApiDoc::openapi().to_pretty_json()?;
    spec.push('\n');
    fs::write("openapi.json", spec)?;

    Ok(())
}
