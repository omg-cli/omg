use anyhow::Result;

pub async fn remove_dry_run(packages: &[String]) -> Result<()> {
    super::generic::remove_dry_run(packages).await
}
