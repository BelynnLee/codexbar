use base64::{Engine as _, engine::general_purpose::STANDARD};
use thiserror::Error;

pub const ENVELOPE_PREFIX: &str = "enc:v1:";

pub trait SecretCodec: Send + Sync + std::fmt::Debug {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError>;
    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError>;
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("Secret envelope is not valid base64: {0}")]
    InvalidEnvelope(#[from] base64::DecodeError),
    #[error("Decrypted secret is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    #[error("{0}")]
    Platform(String),
    #[error("Windows DPAPI is unavailable on this platform")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedSecret {
    Plaintext(String),
    Encrypted(String),
}

pub fn encode_secret(codec: &dyn SecretCodec, value: &str) -> Result<String, SecretError> {
    let protected = codec.protect(value.as_bytes())?;
    Ok(format!("{ENVELOPE_PREFIX}{}", STANDARD.encode(protected)))
}

pub fn decode_secret(codec: &dyn SecretCodec, value: &str) -> Result<DecodedSecret, SecretError> {
    let Some(payload) = value.strip_prefix(ENVELOPE_PREFIX) else {
        return Ok(DecodedSecret::Plaintext(value.to_owned()));
    };
    let protected = STANDARD.decode(payload)?;
    let plaintext = codec.unprotect(&protected)?;
    Ok(DecodedSecret::Encrypted(String::from_utf8(plaintext)?))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DpapiCodec;

#[cfg(windows)]
impl SecretCodec for DpapiCodec {
    fn protect(&self, plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        protect(plaintext)
    }

    fn unprotect(&self, ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        unprotect(ciphertext)
    }
}

#[cfg(not(windows))]
impl SecretCodec for DpapiCodec {
    fn protect(&self, _plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::UnsupportedPlatform)
    }

    fn unprotect(&self, _ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
        Err(SecretError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn protect(plaintext: &[u8]) -> Result<Vec<u8>, SecretError> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };

    let input = input_blob(plaintext)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` borrows `plaintext` for the duration of the call. All optional parameters are
    // null, UI is forbidden, and `output` is copied and released with LocalFree before returning.
    let succeeded = unsafe {
        CryptProtectData(
            &raw const input,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if succeeded == 0 {
        return Err(SecretError::Platform(format!(
            "Windows DPAPI could not protect secret: {}",
            std::io::Error::last_os_error()
        )));
    }
    copy_and_free(output)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, SecretError> {
    use std::ptr;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = input_blob(ciphertext)?;
    let mut output = CRYPT_INTEGER_BLOB::default();
    // SAFETY: `input` borrows `ciphertext` for the duration of the call. All optional parameters are
    // null, UI is forbidden, and `output` is copied and released with LocalFree before returning.
    let succeeded = unsafe {
        CryptUnprotectData(
            &raw const input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    };
    if succeeded == 0 {
        return Err(SecretError::Platform(format!(
            "Windows DPAPI could not unprotect secret: {}",
            std::io::Error::last_os_error()
        )));
    }
    copy_and_free(output)
}

#[cfg(windows)]
fn input_blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, SecretError> {
    use windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB;

    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len())
            .map_err(|_| SecretError::Platform("DPAPI input is too large".into()))?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn copy_and_free(
    output: windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB,
) -> Result<Vec<u8>, SecretError> {
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::LocalFree;

    let result = if output.cbData == 0 {
        Ok(Vec::new())
    } else if output.pbData.is_null() {
        Err(SecretError::Platform(
            "Windows DPAPI returned a null output buffer".into(),
        ))
    } else {
        // SAFETY: successful DPAPI calls return `cbData` readable bytes at `pbData`.
        Ok(unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec())
    };
    // SAFETY: DPAPI allocates `pbData` with LocalAlloc. LocalFree accepts null and releases non-null
    // output exactly once after the bytes have been copied.
    let _ = unsafe { LocalFree(output.pbData.cast::<c_void>()) };
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct XorCodec;

    impl SecretCodec for XorCodec {
        fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            Ok(bytes.iter().map(|byte| byte ^ 0x5a).collect())
        }

        fn unprotect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
            self.protect(bytes)
        }
    }

    #[test]
    fn envelope_round_trips_with_an_injected_codec() {
        let encoded = encode_secret(&XorCodec, "fictional-secret").unwrap();
        assert!(encoded.starts_with(ENVELOPE_PREFIX));
        assert_eq!(
            decode_secret(&XorCodec, &encoded).unwrap(),
            DecodedSecret::Encrypted("fictional-secret".into())
        );
    }

    #[test]
    fn legacy_plaintext_is_returned_without_using_the_codec() {
        assert_eq!(
            decode_secret(&XorCodec, "legacy-secret").unwrap(),
            DecodedSecret::Plaintext("legacy-secret".into())
        );
    }

    #[test]
    fn malformed_base64_envelope_is_rejected() {
        assert!(matches!(
            decode_secret(&XorCodec, "enc:v1:not-base64"),
            Err(SecretError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn invalid_utf8_after_unprotect_is_rejected() {
        #[derive(Debug)]
        struct InvalidUtf8Codec;

        impl SecretCodec for InvalidUtf8Codec {
            fn protect(&self, bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Ok(bytes.to_vec())
            }

            fn unprotect(&self, _bytes: &[u8]) -> Result<Vec<u8>, SecretError> {
                Ok(vec![0xff])
            }
        }

        assert!(matches!(
            decode_secret(&InvalidUtf8Codec, "enc:v1:AA=="),
            Err(SecretError::InvalidUtf8(_))
        ));
    }

    #[cfg(windows)]
    #[test]
    fn windows_dpapi_round_trips_without_ui() {
        let codec = DpapiCodec;
        let plaintext = b"codexbar-dpapi-test";
        let ciphertext = codec.protect(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(codec.unprotect(&ciphertext).unwrap(), plaintext);
    }
}
