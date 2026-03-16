#[cfg(test)]
mod tests {
    use cavos::jwt::base64::base64url_decode_window;
    use cavos::jwt::jwt_parser::{hash_utf8_bytes, parse_decimal, split_signed_data};

    const GOOGLE_ISS: felt252 = 0x68747470733a2f2f6163636f756e74732e676f6f676c652e636f6d;

    fn sample_google_signed_data() -> ByteArray {
        "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Rfa2lkIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhdWQiOiJteV9jbGllbnRfaWQiLCJzdWIiOiIxMjM0NTY3ODkwIiwibm9uY2UiOiIweGRlYWQiLCJleHAiOjE3MDAwMDAwMDB9"
    }

    fn byte_array_to_bytes(data: @ByteArray) -> Array<u8> {
        let mut result: Array<u8> = array![];
        let mut i: usize = 0;
        while i != data.len() {
            result.append(data.at(i).unwrap());
            i += 1;
        }
        result
    }

    fn bytes_to_felt(data: Span<u8>) -> felt252 {
        let mut value = 0_felt252;
        let mut i: usize = 0;
        while i < data.len() && i < 31 {
            let byte: u8 = *data[i];
            value = value * 256 + byte.into();
            i += 1;
        }
        value
    }

    fn decode_payload_window(jwt: @ByteArray, offset: usize, len: usize) -> Array<u8> {
        let (_, payload_start, payload_end) = split_signed_data(jwt);
        let payload_len = payload_end - payload_start;
        base64url_decode_window(jwt, payload_start, payload_len, offset, len)
    }

    #[test]
    fn test_signed_payload_extracts_google_exp_claim() {
        let jwt = sample_google_signed_data();
        let decoded = decode_payload_window(@jwt, 100, 10);
        let exp = parse_decimal(decoded.span());
        assert!(exp == 1700000000, "exp should come from the signed payload");
    }

    #[test]
    #[should_panic]
    fn test_signed_payload_rejects_forged_exp_claim() {
        let jwt = sample_google_signed_data();
        let decoded = decode_payload_window(@jwt, 100, 10);
        let exp = parse_decimal(decoded.span());
        assert!(exp == 9999999999, "forged exp should not match the signed payload");
    }

    #[test]
    fn test_signed_payload_extracts_google_iss_claim() {
        let jwt = sample_google_signed_data();
        let decoded = decode_payload_window(@jwt, 8, 27);
        let iss = bytes_to_felt(decoded.span());
        assert!(iss == GOOGLE_ISS, "iss should come from the signed payload");
    }

    #[test]
    #[should_panic]
    fn test_signed_payload_rejects_forged_iss_claim() {
        let jwt = sample_google_signed_data();
        let decoded = decode_payload_window(@jwt, 8, 27);
        let iss = bytes_to_felt(decoded.span());
        assert!(
            iss == 0x68747470733a2f2f6170706c6569642e6170706c652e636f6d,
            "forged iss should not match the signed payload",
        );
    }

    #[test]
    fn test_signed_payload_extracts_aud_hash() {
        let jwt = sample_google_signed_data();
        let decoded = decode_payload_window(@jwt, 44, 12);
        let aud_hash = hash_utf8_bytes(decoded.span());
        let expected = hash_utf8_bytes(byte_array_to_bytes(@"my_client_id").span());
        assert!(aud_hash == expected, "aud hash should come from the signed payload");
    }

    #[test]
    #[should_panic]
    fn test_signed_payload_rejects_forged_aud_hash() {
        let jwt = sample_google_signed_data();
        let decoded = decode_payload_window(@jwt, 44, 12);
        let aud_hash = hash_utf8_bytes(decoded.span());
        let forged = hash_utf8_bytes(byte_array_to_bytes(@"different_client").span());
        assert!(aud_hash == forged, "forged aud should not match the signed payload");
    }
}
