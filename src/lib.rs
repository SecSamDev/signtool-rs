pub mod params;
pub mod signtool;
pub mod err;

#[ignore]
#[test]
fn test_signtool() {
    use params::*;
    let signtool = signtool::SignTool::new().unwrap();
    signtool.sign(std::path::Path::new("my_exe.exe"), &SignParams::Thumbprint(ThumbprintParams {
        digest_algorithm: SignAlgorithm::Sha256,
        certificate_thumbprint: format!("1fcd13024cf4a254440963990704f207030bf694"),
        timestamp_url: TimestampUrl::Comodo,
    })).unwrap();
}