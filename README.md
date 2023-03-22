# SignTool for Rust
![crates.io](https://img.shields.io/crates/v/signtool.svg)

A library to simplify the usage of Microsoft code signing library (SignTool) for Rust. Inspired by [rust-codesign](https://github.com/forbjok/rust-codesign)

This library is a convenience wrapper around Microsoft's signing tool and requires the Windows SDK to be installed.

#### Usage
```rust
let signtool = signtool::SignTool::new().unwrap();
signtool.sign(std::path::Path::new("my_exe.exe"), &SignParams::Thumbprint(ThumbprintParams {
    digest_algorithm: SignAlgorithm::Sha256,
    certificate_thumbprint: format!("1fcd13024cf4a254440963990704f207030bf694"),
    timestamp_url: TimestampUrl::Comodo,
})).unwrap();
```

