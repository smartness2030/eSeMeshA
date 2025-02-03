mod build_ebpf;
mod run;
mod codegen;

use std::process::exit;

use clap::Parser;
use codegen::generate;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Run(run::Options),
    Codegen,
}

fn main() {
    let opts = Options::parse();

    let ret = match opts.command {
        Command::BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Command::Run(opts) => run::run(opts),
        Command::Codegen => generate(),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
