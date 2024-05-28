#[derive(Clone, Debug, Default, PartialEq)]
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

#[derive(Clone, Debug, Default, PartialEq)]
pub enum TimestampUrl {
    #[default]
    Comodo,
    DigiCert,
    Other(String)
}

impl From<&str> for TimestampUrl {
    fn from(v: &str) -> Self {
        let v_low = v.to_lowercase();
        if v_low == "comodo" {
            Self::Comodo
        }else if v_low == "digicert" {
            Self::DigiCert
        }else {
            Self::Other(v.to_string())
        }
    }
}
impl From<String> for TimestampUrl {
    fn from(v: String) -> Self {
        let v_low = v.to_lowercase();
        if v_low == "comodo" {
            Self::Comodo
        }else if v_low == "digicert" {
            Self::DigiCert
        }else {
            Self::Other(v)
        }
    }
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
/// Sign using CSP.
/// 
/// https://docs.digicert.com/en/digicert-keylocker/signing-tools/sign-authenticode-files-with-signtool-on-windows.html
#[derive(Clone, Debug, Default)]
pub struct CspParams {
    pub name: String,
    pub keypair_alias: String,
    pub digest_algorithm: SignAlgorithm,
    /// Disk location of the Certificate File
    pub certificate_location: String,
    pub timestamp_url: TimestampUrl,
    pub timestamp_digest_algorithm: SignAlgorithm,
}
#[derive(Clone, Debug, Default)]
pub enum SignParams {
    Thumbprint(ThumbprintParams),
    File(FileCertParams),
    Csp(CspParams),
    #[default]
    None
}


#[test]
fn from_timestamp_url_to_param() {
    let timestamp : TimestampUrl = "http://timestamp.digicert.com".into();
    assert_eq!(TimestampUrl::Other("http://timestamp.digicert.com".to_string()), timestamp);
    let timestamp : TimestampUrl = "CoMoDo".into();
    assert_eq!(TimestampUrl::Comodo, timestamp);
    let timestamp : TimestampUrl = "DigiCert".into();
    assert_eq!(TimestampUrl::DigiCert, timestamp);
}