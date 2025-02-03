use anyhow::Error;
use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let base_program_name = "mesh-fastpath-ebpf";
    let out_path = format!("{base_program_name}/src/bindings.rs");
    let names: Vec<&str> = vec![
      "socket",
      "msghdr",
      "sock_common",
    ];

    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;

    let mut out = File::create(PathBuf::from(&out_path))
      .or(Err(Error::msg(format!("couldn't open `{out_path}`"))))?;

    out.write(bindings.as_bytes())?;
    Ok(())
}
