//! Select operator input before creating a VM or sending initialization.
use anyhow::{bail, Context, Result};
use std::{
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, PartialEq)]
enum Source {
    None,
    Directory(PathBuf),
    Prompt,
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "unmeasured-data source directory is unavailable: {}",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!(
            "unmeasured-data source must be a directory: {}",
            path.display()
        );
    }
    Ok(())
}

fn select_source(
    declared: &[String],
    root: Option<&PathBuf>,
    alias: Option<&PathBuf>,
    workload: Option<&PathBuf>,
    skip: bool,
) -> Result<Source> {
    if root.is_some() && alias.is_some() {
        bail!("use either --unmeasured-data-root or deprecated --unmeasured-data-dir, not both");
    }
    if skip && (root.is_some() || alias.is_some()) {
        bail!("--no-unmeasured-data cannot be combined with an unmeasured-data source directory");
    }
    if skip {
        return Ok(Source::None);
    }
    if let Some(path) = root.or(alias) {
        require_directory(path)?;
        return Ok(Source::Directory(path.clone()));
    }
    if declared.is_empty() {
        return Ok(Source::None);
    }
    if let Some(workload) = workload {
        let path = atakit_workload::data::default_unmeasured_data_root(workload);
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                require_directory(&path)?;
                return Ok(Source::Directory(path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect default unmeasured-data directory"),
        }
    }
    Ok(Source::Prompt)
}

pub(super) fn resolve_source(
    declared: &[String],
    root: Option<&PathBuf>,
    alias: Option<&PathBuf>,
    workload: Option<&PathBuf>,
    skip: bool,
) -> Result<Option<PathBuf>> {
    let source = select_source(declared, root, alias, workload, skip)?;
    finish_selection(
        source,
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        &mut std::io::stdin().lock(),
        &mut std::io::stderr().lock(),
    )
}

fn finish_selection(
    source: Source,
    interactive: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<Option<PathBuf>> {
    match source {
        Source::None => Ok(None),
        Source::Directory(path) => Ok(Some(path)),
        Source::Prompt if !interactive => bail!("workload declares unmeasured-data but no source directory is available; pass --unmeasured-data-root DIR or --no-unmeasured-data when running without an interactive terminal"),
        Source::Prompt => prompt(input, output),
    }
}

fn read_line(input: &mut impl BufRead, output: &mut impl Write) -> Result<String> {
    output.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        bail!("deployment cancelled: no unmeasured-data choice supplied");
    }
    Ok(line.trim().to_owned())
}

fn prompt(input: &mut impl BufRead, output: &mut impl Write) -> Result<Option<PathBuf>> {
    loop {
        writeln!(output, "No unmeasured-data source directory is available.\n  1. Provide a directory\n  2. Continue without unmeasured data\n  3. Cancel deployment")?;
        write!(output, "Choose [1/2/3, default 3]: ")?;
        match read_line(input, output)?.as_str() {
            "1" => {
                write!(output, "Source directory: ")?;
                let path = PathBuf::from(read_line(input, output)?);
                match require_directory(&path) {
                    Ok(()) => return Ok(Some(path)),
                    Err(error) => writeln!(output, "{error:#}")?,
                }
            }
            "2" => return Ok(None),
            "" | "3" => {
                bail!("deployment cancelled before creating a VM or sending initialization")
            }
            _ => writeln!(output, "Enter 1, 2, or 3.")?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_explicit_and_absent_sources_are_distinct() {
        let tmp = tempfile::tempdir().unwrap();
        let workload = tmp.path().to_owned();
        let declared = vec!["config/key".into()];
        assert_eq!(
            select_source(&declared, None, None, Some(&workload), false).unwrap(),
            Source::Prompt
        );
        assert_eq!(
            select_source(&declared, None, None, None, false).unwrap(),
            Source::Prompt
        );
        assert_eq!(
            select_source(&[], None, None, None, false).unwrap(),
            Source::None
        );
        assert_eq!(
            select_source(&declared, None, None, None, true).unwrap(),
            Source::None
        );
        let root = workload.join("unmeasured-data");
        assert!(select_source(&declared, Some(&root), None, None, false).is_err());
        std::fs::write(&root, "not a directory").unwrap();
        assert!(select_source(&declared, None, None, Some(&workload), false).is_err());
        std::fs::remove_file(&root).unwrap();
        std::fs::create_dir(&root).unwrap();
        for source in [
            select_source(&declared, None, None, Some(&workload), false),
            select_source(&declared, Some(&root), None, None, false),
            select_source(&declared, None, Some(&root), None, false),
        ] {
            assert_eq!(source.unwrap(), Source::Directory(root.clone()));
        }
        assert!(select_source(&declared, Some(&root), None, None, true).is_err());
        assert!(select_source(&declared, Some(&root), Some(&root), None, false).is_err());
    }

    #[test]
    fn prompt_supports_directory_skip_cancel_and_invalid_input() {
        let tmp = tempfile::tempdir().unwrap();
        let mut output = Vec::new();
        let answers = format!(
            "invalid\n1\n{}\n1\n{}\n",
            tmp.path().join("missing").display(),
            tmp.path().display()
        );
        assert_eq!(
            prompt(&mut answers.as_bytes(), &mut output).unwrap(),
            Some(tmp.path().to_owned())
        );
        assert!(String::from_utf8(output)
            .unwrap()
            .contains("Enter 1, 2, or 3"));
        assert_eq!(
            prompt(&mut "2\n".as_bytes(), &mut Vec::new()).unwrap(),
            None
        );
        for input in ["3\n", "\n", ""] {
            assert!(prompt(&mut input.as_bytes(), &mut Vec::new())
                .unwrap_err()
                .to_string()
                .contains("cancelled"));
        }
    }

    #[test]
    fn noninteractive_requires_an_explicit_choice_without_reading_input() {
        let mut input = "2\n".as_bytes();
        let mut output = Vec::new();
        let error = finish_selection(Source::Prompt, false, &mut input, &mut output).unwrap_err();
        assert!(error.to_string().contains("--no-unmeasured-data"));
        assert_eq!(input, b"2\n");
        assert!(output.is_empty());
        assert_eq!(
            finish_selection(Source::None, false, &mut input, &mut output).unwrap(),
            None
        );
    }
}
