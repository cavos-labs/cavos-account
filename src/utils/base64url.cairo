/// Base64URL decode utilities for JWKS key verification.
/// Re-exports the base64url decoder from the jwt module for use in trustless key registration.
pub use crate::jwt::base64::{base64url_decode, base64url_decode_window};
