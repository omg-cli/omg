use crate::common::TestProject;

pub fn seed_installed(project: &TestProject, runtime: &str, versions: &[&str]) {
    let directory = project.data_dir.path().join("versions").join(runtime);
    for version in versions {
        std::fs::create_dir_all(directory.join(version)).unwrap();
    }
}

pub fn installed_rows(stdout: &str) -> Vec<&str> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with('•'))
        .collect()
}
