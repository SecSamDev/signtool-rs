#[derive(Clone, Debug, Default)]
pub enum SignAlgorithm {
    Sha512,
    #[default]
    Sha256,
    Sha1
}

impl std::fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignAlgorithm::Sha512 => f.write_str("SHA512"),
            SignAlgorithm::Sha256 => f.write_str("SHA256"),
            SignAlgorithm::Sha1 => f.write_str("SHA1"),
        }
    }
}
impl Into<&'static str> for SignAlgorithm {
    fn into(self) -> &'static str {
        match self {
            SignAlgorithm::Sha512 => "SHA512",
            SignAlgorithm::Sha256 => "SHA256",
            SignAlgorithm::Sha1 => "SHA1",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum TimestampUrl {
    #[default]
    Comodo,
    DigiCert,
    Other(String)
}

#[derive(Clone, Debug, Default)]
pub struct ThumbprintParams {
    pub digest_algorithm: SignAlgorithm,
    /// Thumbprint of the certificate in SHA1 format
    pub certificate_thumbprint: String,
    pub timestamp_url: TimestampUrl,
}
#[derive(Clone, Debug, Default)]
pub struct FileCertParams {
    pub digest_algorithm: SignAlgorithm,
    /// Disk location of the Certificate File
    pub certificate_location: String,
    pub certificate_password : Option<String>,
    pub timestamp_url: TimestampUrl,
}
#[derive(Clone, Debug, Default)]
pub enum SignParams {
    Thumbprint(ThumbprintParams),
    File(FileCertParams),
    #[default]
    None
}