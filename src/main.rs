use arach_package_lint::{parse_cosmic_lock, validate_tree, verify_cosmic_repository};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut root = PathBuf::from(".");
    let mut upstream = None;
    let mut arguments = env::args_os().skip(1);
    while let Some(flag) = arguments.next() {
        let Some(value) = arguments.next() else {
            return usage();
        };
        if flag == "--root" {
            root = PathBuf::from(value);
        } else if flag == "--verify-cosmic-repository" {
            upstream = Some(PathBuf::from(value));
        } else {
            return usage();
        }
    }

    match validate_tree(&root) {
        Ok(report) => {
            if let Some(repository) = upstream {
                let lock_path = root.join("locks/cosmic-epoch.toml");
                let lock_text = match fs::read_to_string(&lock_path) {
                    Ok(text) => text,
                    Err(error) => {
                        eprintln!("{}: {error}", lock_path.display());
                        return ExitCode::FAILURE;
                    }
                };
                let lock = match parse_cosmic_lock(&lock_text) {
                    Ok(lock) => lock,
                    Err(error) => {
                        eprintln!("{}: {error}", lock_path.display());
                        return ExitCode::FAILURE;
                    }
                };
                if let Err(error) = verify_cosmic_repository(&lock, &repository) {
                    eprintln!("{error}");
                    return ExitCode::FAILURE;
                }
            }
            println!(
                "validated {} recipes, {} locks, and {} COSMIC components",
                report.recipes, report.locks, report.cosmic_components
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: arach-package-lint [--root PATH] [--verify-cosmic-repository PATH]");
    ExitCode::from(2)
}
