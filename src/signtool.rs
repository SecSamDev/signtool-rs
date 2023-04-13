use std::path::{Path, PathBuf};
use forensic_rs::prelude::RegistryReader;

use crate::{ err::SignToolError, params::{SignParams, TimestampUrl}};
use forensic_rs::prelude::RegHiveKey::*;

const INSTALLED_ROOTS: &str = r"SOFTWARE\Microsoft\Windows Kits\Installed Roots";

pub struct SignTool {
    signtool_path: PathBuf,
}

impl SignTool {
    pub fn new() -> Result<SignTool, SignToolError> {
        Ok(SignTool {
            signtool_path: locate_signtool()?,
        })
    }
    /**
     * Instantiate SignTool for a kit. Ex: KitsRoot10
     */
    pub fn for_kit(kit : &str) -> Result<SignTool, SignToolError> {
        Ok(SignTool {
            signtool_path: signtool_for_kit(kit)?,
        })
    }
    pub fn kit10() -> Result<SignTool, SignToolError> {
        Ok(SignTool {
            signtool_path: signtool_for_kit("KitsRoot10")?,
        })
    }
    pub fn kit8_1() -> Result<SignTool, SignToolError> {
        Ok(SignTool {
            signtool_path: signtool_for_kit("KitsRoot81")?,
        })
    }

    pub fn sign<P: AsRef<Path>>(&self, path: P, params: &SignParams) -> Result<(), SignToolError> {
        use std::process::Command;

        // Construct SignTool command
        let mut cmd = Command::new(&self.signtool_path);
        let args = args_from_params(params)?;
        cmd.args(args);

        cmd.arg(path.as_ref());
        // Execute SignTool command
        let output = cmd.output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(output.stderr.as_slice()).into_owned();
            Err(SignToolError::SignToolError {
                exit_code: output.status.code().unwrap_or(-1),
                stderr: stderr,
            })?;
        }
        Ok(())
    }
}

fn timestamp_url(url : &TimestampUrl) -> &str {
    match url {
        TimestampUrl::DigiCert => "http://timestamp.digicert.com",
        TimestampUrl::Comodo => "http://timestamp.comodoca.com",
        TimestampUrl::Other(v) => &v[..],
    }
} 

fn args_from_params(params: &SignParams) -> Result<Vec<&str>, SignToolError> {
    Ok(match params {
        SignParams::Thumbprint(params) => {
            vec![
                "sign",
                "/a",
                "/fd", params.digest_algorithm.clone().into(),
                "/sha1", &params.certificate_thumbprint[..],
                "/t", timestamp_url(&params.timestamp_url)
            ]
        },
        SignParams::File(params) => {
            let mut args = vec![
                "sign",
                "/a",
                "/fd", params.digest_algorithm.clone().into(),
                "/f", &params.certificate_location[..],
                "/t", timestamp_url(&params.timestamp_url)
            ];
            if let Some(password) = &params.certificate_password {
                args.push("/p");
                args.push(&password[..]);
            }
            args
        },
        SignParams::None => return Err(SignToolError::Other(format!("Cannot sign an executable without parameters"))),
    })
}

fn get_kits() -> Result<Vec<String>, SignToolError> {
    let reg_reader = frnsc_liveregistry_rs::LiveRegistryReader::new();
    let installed_roots_key = reg_reader.open_key(HkeyLocalMachine, INSTALLED_ROOTS)?;
    let kits = reg_reader.enumerate_values(installed_roots_key)?.into_iter()
        .filter(|res| res.starts_with("KitsRoot"))
        .collect();
    Ok(kits)
}

fn locate_signtool() -> Result<PathBuf, SignToolError> {
    let reg_reader = frnsc_liveregistry_rs::LiveRegistryReader::new();
    let installed_roots_key = reg_reader.open_key(HkeyLocalMachine, INSTALLED_ROOTS)?;
    let mut kits = get_kits()?;
    let kit = if kits.len() == 1 {
        kits.remove(0)
    }else if kits.len() == 0 {
        return Err(SignToolError::Other(format!("Cannot locate sign tool, no valid Kit")));
    }else {
        if let Some(pos) = kits.iter().position(|v| v == &"KitsRoot10") {
            kits.remove(pos)
        }else {
            kits.remove(0)
        }
    };
    let kits_root_path : String = reg_reader.read_value(installed_roots_key, kit.as_str())?.try_into()?;
    let kits_root_bin_path = Path::new(&kits_root_path).join("bin");

    let mut installed_kits: Vec<String> = reg_reader.enumerate_keys(installed_roots_key)?;
    installed_kits.sort();

    let mut kit_bin_paths: Vec<PathBuf> = installed_kits
        .iter()
        .rev()
        .map(|kit| kits_root_bin_path.join(kit).to_path_buf())
        .collect();

    kit_bin_paths.push(kits_root_bin_path.to_path_buf());

    #[cfg(target_arch = "x86")]
    let arch_dir = "x86";
    #[cfg(target_arch = "x86_64")]
    let arch_dir = "x64";
    #[cfg(target_arch = "aarch64")]
    let arch_dir = "arm64";
    #[cfg(target_arch = "arm")]
    let arch_dir = "arm";

    for kit_bin_path in &kit_bin_paths {
        let signtool_path = kit_bin_path.join(arch_dir).join("signtool.exe");
        if signtool_path.exists() {
            return Ok(signtool_path.to_path_buf());
        }
    }
    Err("No SignTool found!".to_owned())?
}

fn signtool_for_kit(kit : &str) -> Result<PathBuf, SignToolError> {
    let reg_reader = frnsc_liveregistry_rs::LiveRegistryReader::new();
    let installed_roots_key = reg_reader.open_key(HkeyLocalMachine, INSTALLED_ROOTS)?;
    let kits_root_path : String = reg_reader.read_value(installed_roots_key, kit)?.try_into()?;

    let kits_root_bin_path = Path::new(&kits_root_path).join("bin");

    let mut installed_kits: Vec<String> = reg_reader.enumerate_keys(installed_roots_key)?;
    installed_kits.sort();
    let mut kit_bin_paths: Vec<PathBuf> = installed_kits
        .iter()
        .rev()
        .map(|kit| kits_root_bin_path.join(kit).to_path_buf())
        .collect();

    kit_bin_paths.push(kits_root_bin_path.to_path_buf());

    #[cfg(target_arch = "x86")]
    let arch_dir = "x86";
    #[cfg(target_arch = "x86_64")]
    let arch_dir = "x64";
    #[cfg(target_arch = "aarch64")]
    let arch_dir = "arm64";
    #[cfg(target_arch = "arm")]
    let arch_dir = "arm";

    for kit_bin_path in &kit_bin_paths {
        let signtool_path = kit_bin_path.join(arch_dir).join("signtool.exe");
        if signtool_path.exists() {
            return Ok(signtool_path.to_path_buf());
        }
    }
    Err("No SignTool found!".to_owned())?
}