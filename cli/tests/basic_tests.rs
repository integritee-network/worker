use clap::Parser;
use integritee_cli::Cli;

fn init() {
	let _ = env_logger::try_init();
}

#[test]
fn test_version() {
	init();

	let res = Cli::try_parse_from(vec!["placeholder_cli_path", "--version"]);

	assert!(matches!(res, Err(clap::Error { kind: clap::ErrorKind::DisplayVersion, .. })));
}

#[test]
fn test_help() {
	init();

	let res = Cli::try_parse_from(vec!["placeholder_cli_path", "--help"]);

	assert!(matches!(res, Err(clap::Error { kind: clap::ErrorKind::DisplayHelp, .. })));
}
