//! Client-side MFA helpers.
//!
//! The enrollment secret and `otpauth://` URI come from the server; this
//! renders that URI as a scannable QR code so the user can add it to an
//! authenticator app. The SVG is self-contained (no external resources), so it
//! is safe to inline under the app's `default-src 'self'` CSP.

use qrcode::render::svg;
use qrcode::QrCode;

/// Render an `otpauth://` URI as a standalone SVG string.
pub fn totp_qr_svg(otpauth_uri: &str) -> Result<String, String> {
    let code = QrCode::new(otpauth_uri.as_bytes()).map_err(|e| e.to_string())?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_a_self_contained_svg() {
        let uri = "otpauth://totp/Basementen%20Vault:alice@example.com\
                   ?secret=JBSWY3DPEHPK3PXP&issuer=Basementen%20Vault&algorithm=SHA1&digits=6&period=30";
        let svg = totp_qr_svg(uri).unwrap();
        assert!(svg.contains("<svg"), "produces an SVG element");
        // No scripts and no external resource fetches (only the SVG namespace,
        // which is a declaration, not a request).
        assert!(!svg.contains("<script"), "no scripts");
        assert!(!svg.contains("<image"), "no embedded/remote images");
        assert!(svg.len() > 200, "non-trivial output");
    }

    #[test]
    fn empty_uri_still_encodes() {
        // QR of an empty string is valid; we just never call it that way.
        assert!(totp_qr_svg("").is_ok());
    }
}
