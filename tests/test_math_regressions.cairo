#[cfg(test)]
mod tests {
    use cavos::cavos_account::CavosAccount::{
        SessionTimeLimits, SessionTimeLimitsStorePacking, SessionUsageLimits,
        SessionUsageLimitsStorePacking, oauth_policy_start,
    };
    use cavos::jwt::base64::base64url_decode_window;
    use cavos::jwt::jwt_parser::{
        hash_utf8_bytes, parse_decimal, parse_hex, split_signed_data, find_byte,
    };
    use cavos::utils::address_seed::{compute_address_seed, verify_address_seed};
    use cavos::utils::nonce::{compute_nonce, verify_nonce};

    fn byte_array_to_bytes(data: @ByteArray) -> Array<u8> {
        let mut result: Array<u8> = array![];
        let mut i: usize = 0;
        while i != data.len() {
            result.append(data.at(i).unwrap());
            i += 1;
        }
        result
    }

    /// Build a minimal signature array for oauth_policy_start tests.
    /// Layout: 25 zeros | 864 (garaga_len) | 864 zeros | jwt_bytes_len | ceil(len/31) zeros
    fn build_oauth_signature_prefix(jwt_bytes_len: usize) -> Array<felt252> {
        let mut signature: Array<felt252> = array![];

        // Indices [0..24]: header fields before GARAGA_RSA_START=25
        let mut i: usize = 0;
        while i != 25 {
            signature.append(0);
            i += 1;
        }

        // Index [25]: garaga_rsa_len = 864
        signature.append(864);

        // Indices [26..889]: garaga witness data (864 felts)
        i = 0;
        while i != 864 {
            signature.append(0);
            i += 1;
        }

        // Index [890]: jwt_bytes_len
        signature.append(jwt_bytes_len.into());

        // Indices [891..]: packed JWT chunks (ceil(jwt_bytes_len / 31))
        let jwt_chunks = (jwt_bytes_len + 30) / 31;
        i = 0;
        while i != jwt_chunks {
            signature.append(0);
            i += 1;
        }

        signature
    }

    // ── base64url_decode_window ──────────────────────────────────────────────

    #[test]
    fn test_base64url_decode_window_handles_two_char_tail() {
        // "QQ" = base64url for [65] ('A'), window extracts byte 0
        let input = "QQ";
        let decoded = base64url_decode_window(@input, 0, 2, 0, 1);
        let span = decoded.span();
        assert!(span.len() == 1, "wrong decoded length");
        assert!(*span[0] == 65_u8, "wrong decoded byte");
    }

    #[test]
    fn test_base64url_decode_window_handles_three_char_tail() {
        // "SGk" = base64url for [72, 105] ("Hi"), window extracts byte 1
        let input = "SGk";
        let decoded = base64url_decode_window(@input, 0, 3, 1, 1);
        let span = decoded.span();
        assert!(span.len() == 1, "wrong decoded length");
        assert!(*span[0] == 105_u8, "wrong decoded byte");
    }

    #[test]
    fn test_base64url_decode_window_handles_cross_chunk_tail_window() {
        // "SGVsbG8" = base64url for "Hello" [72,101,108,108,111], window extracts last byte
        let input = "SGVsbG8";
        let decoded = base64url_decode_window(@input, 0, 7, 4, 1);
        let span = decoded.span();
        assert!(span.len() == 1, "wrong decoded length");
        assert!(*span[0] == 111_u8, "wrong decoded byte 'o'");
    }

    #[test]
    fn test_base64url_decode_window_full_four_char_group() {
        // "AQID" = base64url for [1, 2, 3]
        let input = "AQID";
        let decoded = base64url_decode_window(@input, 0, 4, 0, 3);
        let span = decoded.span();
        assert!(span.len() == 3, "wrong decoded length");
        assert!(*span[0] == 1_u8, "byte 0 wrong");
        assert!(*span[1] == 2_u8, "byte 1 wrong");
        assert!(*span[2] == 3_u8, "byte 2 wrong");
    }

    #[test]
    fn test_base64url_decode_window_full_hello() {
        // "SGVsbG8" = base64url for "Hello" [72,101,108,108,111]
        let input = "SGVsbG8";
        let decoded = base64url_decode_window(@input, 0, 7, 0, 5);
        let span = decoded.span();
        assert!(span.len() == 5, "wrong decoded length");
        assert!(*span[0] == 72_u8, "'H'");
        assert!(*span[1] == 101_u8, "'e'");
        assert!(*span[2] == 108_u8, "'l'");
        assert!(*span[3] == 108_u8, "'l'");
        assert!(*span[4] == 111_u8, "'o'");
    }

    #[test]
    fn test_base64url_decode_window_middle_bytes() {
        // "AQID" = [1, 2, 3]; extract only byte 1
        let input = "AQID";
        let decoded = base64url_decode_window(@input, 0, 4, 1, 1);
        let span = decoded.span();
        assert!(span.len() == 1, "wrong length");
        assert!(*span[0] == 2_u8, "middle byte wrong");
    }

    // ── StorePacking roundtrips ───────────────────────────────────────────────

    #[test]
    fn test_session_time_limits_pack_unpack_roundtrip() {
        let original = SessionTimeLimits {
            valid_after: 0x1122334455667788_u64,
            valid_until: 0x99aabbccddeeff00_u64,
            registered_at: 0x0123456789abcdef_u64,
        };
        let packed = SessionTimeLimitsStorePacking::pack(original);
        let unpacked = SessionTimeLimitsStorePacking::unpack(packed);

        assert!(unpacked.valid_after == original.valid_after, "valid_after mismatch");
        assert!(unpacked.valid_until == original.valid_until, "valid_until mismatch");
        assert!(unpacked.registered_at == original.registered_at, "registered_at mismatch");
    }

    #[test]
    fn test_session_time_limits_pack_unpack_zeros() {
        let original = SessionTimeLimits {
            valid_after: 0_u64, valid_until: 0_u64, registered_at: 0_u64,
        };
        let packed = SessionTimeLimitsStorePacking::pack(original);
        let unpacked = SessionTimeLimitsStorePacking::unpack(packed);
        assert!(unpacked.valid_after == 0, "valid_after should be 0");
        assert!(unpacked.valid_until == 0, "valid_until should be 0");
        assert!(unpacked.registered_at == 0, "registered_at should be 0");
    }

    #[test]
    fn test_session_time_limits_pack_unpack_max_values() {
        let original = SessionTimeLimits {
            valid_after: 0xFFFFFFFFFFFFFFFF_u64,
            valid_until: 0xFFFFFFFFFFFFFFFF_u64,
            registered_at: 0xFFFFFFFFFFFFFFFF_u64,
        };
        let packed = SessionTimeLimitsStorePacking::pack(original);
        let unpacked = SessionTimeLimitsStorePacking::unpack(packed);
        assert!(unpacked.valid_after == original.valid_after, "valid_after max mismatch");
        assert!(unpacked.valid_until == original.valid_until, "valid_until max mismatch");
        assert!(unpacked.registered_at == original.registered_at, "registered_at max mismatch");
    }

    #[test]
    fn test_session_usage_limits_pack_unpack_roundtrip_high_epoch() {
        let original = SessionUsageLimits {
            renewal_deadline: 0x0123456789abcdef_u64,
            max_calls_per_tx: 0x89abcdef_u32,
            revocation_epoch: 0x1122334455667788_u64,
        };
        let packed = SessionUsageLimitsStorePacking::pack(original);
        let unpacked = SessionUsageLimitsStorePacking::unpack(packed);

        assert!(
            unpacked.renewal_deadline == original.renewal_deadline, "renewal_deadline mismatch",
        );
        assert!(unpacked.max_calls_per_tx == original.max_calls_per_tx, "max_calls mismatch");
        assert!(
            unpacked.revocation_epoch == original.revocation_epoch, "revocation_epoch mismatch",
        );
    }

    #[test]
    fn test_session_usage_limits_pack_unpack_zeros() {
        let original = SessionUsageLimits {
            renewal_deadline: 0_u64, max_calls_per_tx: 0_u32, revocation_epoch: 0_u64,
        };
        let packed = SessionUsageLimitsStorePacking::pack(original);
        let unpacked = SessionUsageLimitsStorePacking::unpack(packed);
        assert!(unpacked.renewal_deadline == 0, "renewal_deadline should be 0");
        assert!(unpacked.max_calls_per_tx == 0, "max_calls_per_tx should be 0");
        assert!(unpacked.revocation_epoch == 0, "revocation_epoch should be 0");
    }

    #[test]
    fn test_session_usage_limits_pack_unpack_max_values() {
        let original = SessionUsageLimits {
            renewal_deadline: 0xFFFFFFFFFFFFFFFF_u64,
            max_calls_per_tx: 0xFFFFFFFF_u32,
            revocation_epoch: 0xFFFFFFFFFFFFFFFF_u64,
        };
        let packed = SessionUsageLimitsStorePacking::pack(original);
        let unpacked = SessionUsageLimitsStorePacking::unpack(packed);
        assert!(unpacked.renewal_deadline == original.renewal_deadline, "deadline max mismatch");
        assert!(unpacked.max_calls_per_tx == original.max_calls_per_tx, "max_calls max mismatch");
        assert!(unpacked.revocation_epoch == original.revocation_epoch, "epoch max mismatch");
    }

    // ── parse_decimal ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_decimal_zero() {
        let parsed = parse_decimal(byte_array_to_bytes(@"0").span());
        assert!(parsed == 0, "zero should parse to 0");
    }

    #[test]
    fn test_parse_decimal_small_values() {
        assert!(parse_decimal(byte_array_to_bytes(@"1").span()) == 1, "1");
        assert!(parse_decimal(byte_array_to_bytes(@"255").span()) == 255, "255");
        assert!(parse_decimal(byte_array_to_bytes(@"1000").span()) == 1000, "1000");
    }

    #[test]
    fn test_parse_decimal_leading_zeros() {
        let parsed = parse_decimal(byte_array_to_bytes(@"007").span());
        assert!(parsed == 7, "leading zeros should be ignored");
    }

    #[test]
    fn test_parse_decimal_accepts_max_felt() {
        let value = "3618502788666131213697322783095070105623107215331596699973092056135872020480";
        let parsed = parse_decimal(byte_array_to_bytes(@value).span());
        assert!(
            parsed == 0x800000000000011000000000000000000000000000000000000000000000000,
            "unexpected decimal parse result",
        );
    }

    #[test]
    #[should_panic]
    fn test_parse_decimal_rejects_field_modulus() {
        let value = "3618502788666131213697322783095070105623107215331596699973092056135872020481";
        let _ = parse_decimal(byte_array_to_bytes(@value).span());
    }

    #[test]
    #[should_panic]
    fn test_parse_decimal_rejects_non_digit() {
        let _ = parse_decimal(byte_array_to_bytes(@"123x456").span());
    }

    // ── parse_hex ─────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_hex_zero() {
        let parsed = parse_hex(byte_array_to_bytes(@"0x0").span());
        assert!(parsed == 0, "0x0 should be 0");
    }

    #[test]
    fn test_parse_hex_small_values() {
        assert!(parse_hex(byte_array_to_bytes(@"0x1").span()) == 1, "0x1");
        assert!(parse_hex(byte_array_to_bytes(@"0xff").span()) == 255, "0xff");
        assert!(parse_hex(byte_array_to_bytes(@"0x100").span()) == 256, "0x100");
    }

    #[test]
    fn test_parse_hex_uppercase() {
        let lower = parse_hex(byte_array_to_bytes(@"0xff").span());
        let upper = parse_hex(byte_array_to_bytes(@"0xFF").span());
        assert!(lower == upper, "case should not matter");
        assert!(lower == 255, "value should be 255");
    }

    #[test]
    fn test_parse_hex_without_prefix() {
        let parsed = parse_hex(byte_array_to_bytes(@"ff").span());
        assert!(parsed == 255, "hex without 0x prefix should parse");
    }

    #[test]
    fn test_parse_hex_accepts_max_felt() {
        let value = "0x800000000000011000000000000000000000000000000000000000000000000";
        let parsed = parse_hex(byte_array_to_bytes(@value).span());
        assert!(
            parsed == 0x800000000000011000000000000000000000000000000000000000000000000,
            "unexpected hex parse result",
        );
    }

    #[test]
    #[should_panic]
    fn test_parse_hex_rejects_field_modulus() {
        let value = "0x800000000000011000000000000000000000000000000000000000000000001";
        let _ = parse_hex(byte_array_to_bytes(@value).span());
    }

    // ── hash_utf8_bytes ───────────────────────────────────────────────────────

    #[test]
    fn test_hash_utf8_bytes_uses_full_input_not_prefix() {
        let left = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX";
        let right = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaY";
        let left_hash = hash_utf8_bytes(byte_array_to_bytes(@left).span());
        let right_hash = hash_utf8_bytes(byte_array_to_bytes(@right).span());
        assert!(left_hash != right_hash, "hash should not truncate to 31-byte prefix");
    }

    #[test]
    fn test_hash_utf8_bytes_deterministic() {
        let input = "1E6VioIaNI";
        let h1 = hash_utf8_bytes(byte_array_to_bytes(@input).span());
        let h2 = hash_utf8_bytes(byte_array_to_bytes(@input).span());
        assert!(h1 == h2, "same input must produce same hash");
        assert!(h1 != 0, "hash should be non-zero");
    }

    #[test]
    fn test_hash_utf8_bytes_distinct_inputs() {
        let h1 = hash_utf8_bytes(byte_array_to_bytes(@"a").span());
        let h2 = hash_utf8_bytes(byte_array_to_bytes(@"b").span());
        assert!(h1 != h2, "different inputs must produce different hashes");
    }

    #[test]
    fn test_hash_utf8_bytes_order_sensitive() {
        let h1 = hash_utf8_bytes(byte_array_to_bytes(@"ab").span());
        let h2 = hash_utf8_bytes(byte_array_to_bytes(@"ba").span());
        assert!(h1 != h2, "hash must be order-sensitive");
    }

    // ── find_byte / split_signed_data ─────────────────────────────────────────

    #[test]
    fn test_find_byte_found() {
        let data: ByteArray = "hello.world";
        let idx = find_byte(@data, '.', 0);
        assert!(idx == Option::Some(5), "dot should be at index 5");
    }

    #[test]
    fn test_find_byte_not_found() {
        let data: ByteArray = "hello";
        let idx = find_byte(@data, '.', 0);
        assert!(idx == Option::None, "no dot should return None");
    }

    #[test]
    fn test_find_byte_with_offset() {
        let data: ByteArray = "a.b.c";
        // skip first dot at 1, find second dot from index 2
        let idx = find_byte(@data, '.', 2);
        assert!(idx == Option::Some(3), "second dot should be at index 3");
    }

    #[test]
    fn test_split_signed_data_basic() {
        // "aaa.bbb" → header_end=3, payload_start=4, payload_end=7
        let signed: ByteArray = "aaa.bbb";
        let (header_end, payload_start, payload_end) = split_signed_data(@signed);
        assert!(header_end == 3, "header_end wrong");
        assert!(payload_start == 4, "payload_start wrong");
        assert!(payload_end == 7, "payload_end wrong");
    }

    // ── address_seed ─────────────────────────────────────────────────────────

    #[test]
    fn test_compute_address_seed_deterministic() {
        let s1 = compute_address_seed(1, 42, 7);
        let s2 = compute_address_seed(1, 42, 7);
        assert!(s1 == s2, "same inputs must produce same seed");
        assert!(s1 != 0, "seed should be non-zero");
    }

    #[test]
    fn test_compute_address_seed_sub_sensitive() {
        let s1 = compute_address_seed(9, 1, 0);
        let s2 = compute_address_seed(9, 2, 0);
        assert!(s1 != s2, "different sub must produce different seed");
    }

    #[test]
    fn test_compute_address_seed_issuer_sensitive() {
        let s1 = compute_address_seed(1, 99, 0);
        let s2 = compute_address_seed(2, 99, 0);
        assert!(s1 != s2, "different issuers must produce different seed");
    }

    #[test]
    fn test_compute_address_seed_salt_sensitive() {
        let s1 = compute_address_seed(5, 0, 1);
        let s2 = compute_address_seed(5, 0, 2);
        assert!(s1 != s2, "different salt must produce different seed");
    }

    #[test]
    fn test_compute_address_seed_order_sensitive() {
        let s1 = compute_address_seed(1, 2, 3);
        let s2 = compute_address_seed(2, 1, 3);
        assert!(s1 != s2, "seed must be order-sensitive (issuer, sub, salt)");
    }

    #[test]
    fn test_verify_address_seed_correct() {
        let seed = compute_address_seed(7, 99, 42);
        assert!(verify_address_seed(seed, 7, 99, 42), "correct seed should verify");
    }

    #[test]
    fn test_verify_address_seed_wrong_sub() {
        let seed = compute_address_seed(7, 99, 42);
        assert!(!verify_address_seed(seed, 7, 100, 42), "wrong sub should not verify");
    }

    #[test]
    fn test_verify_address_seed_wrong_issuer() {
        let seed = compute_address_seed(7, 99, 42);
        assert!(!verify_address_seed(seed, 8, 99, 42), "wrong issuer should not verify");
    }

    #[test]
    fn test_verify_address_seed_wrong_salt() {
        let seed = compute_address_seed(7, 99, 42);
        assert!(!verify_address_seed(seed, 7, 99, 43), "wrong salt should not verify");
    }

    // ── nonce ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_compute_nonce_deterministic() {
        let n1 = compute_nonce(1, 2, 3, 4);
        let n2 = compute_nonce(1, 2, 3, 4);
        assert!(n1 == n2, "same inputs must produce same nonce");
        assert!(n1 != 0, "nonce should be non-zero");
    }

    #[test]
    fn test_compute_nonce_all_inputs_matter() {
        let base = compute_nonce(1, 2, 3, 4);
        assert!(compute_nonce(9, 2, 3, 4) != base, "eph_pubkey_lo change should affect nonce");
        assert!(compute_nonce(1, 9, 3, 4) != base, "eph_pubkey_hi change should affect nonce");
        assert!(compute_nonce(1, 2, 9, 4) != base, "max_block change should affect nonce");
        assert!(compute_nonce(1, 2, 3, 9) != base, "randomness change should affect nonce");
    }

    #[test]
    fn test_verify_nonce_correct() {
        let nonce = compute_nonce(10, 20, 30, 40);
        assert!(verify_nonce(nonce, 10, 20, 30, 40), "correct nonce should verify");
    }

    #[test]
    fn test_verify_nonce_wrong_value() {
        let nonce = compute_nonce(10, 20, 30, 40);
        assert!(!verify_nonce(nonce + 1, 10, 20, 30, 40), "wrong nonce should not verify");
    }

    // ── oauth_policy_start ────────────────────────────────────────────────────

    #[test]
    fn test_oauth_policy_start_skips_witnesses_before_jwt_chunks() {
        // jwt_bytes_len=62 → jwt_chunks=2 → policy_start = 25+1+864+1+2 = 893
        let signature = build_oauth_signature_prefix(62);
        let policy_start = oauth_policy_start(signature.span());
        assert!(policy_start == 893, "policy_start should be 893 for 62-byte JWT");
    }

    #[test]
    fn test_oauth_policy_start_zero_jwt_bytes() {
        // jwt_bytes_len=0 → jwt_chunks=0 → policy_start = 890 + 1 + 0 = 891
        let signature = build_oauth_signature_prefix(0);
        let policy_start = oauth_policy_start(signature.span());
        assert!(policy_start == 891, "policy_start should be 891 for empty JWT");
    }

    #[test]
    fn test_oauth_policy_start_exactly_one_chunk() {
        // jwt_bytes_len=31 → jwt_chunks=1 → policy_start = 890 + 1 + 1 = 892
        let signature = build_oauth_signature_prefix(31);
        let policy_start = oauth_policy_start(signature.span());
        assert!(policy_start == 892, "policy_start should be 892 for 31-byte JWT");
    }

    #[test]
    fn test_oauth_policy_start_chunk_boundary() {
        // jwt_bytes_len=32 → jwt_chunks=2 → policy_start = 890 + 1 + 2 = 893
        let signature = build_oauth_signature_prefix(32);
        let policy_start = oauth_policy_start(signature.span());
        assert!(policy_start == 893, "policy_start should be 893 for 32-byte JWT");
    }

    #[test]
    fn test_oauth_policy_start_three_chunks() {
        // jwt_bytes_len=93 → jwt_chunks=3 → policy_start = 890 + 1 + 3 = 894
        let signature = build_oauth_signature_prefix(93);
        let policy_start = oauth_policy_start(signature.span());
        assert!(policy_start == 894, "policy_start should be 894 for 93-byte JWT");
    }

    #[test]
    #[should_panic(expected: "Garaga RSA data must be 864 felts")]
    fn test_oauth_policy_start_rejects_wrong_garaga_len() {
        // Build a signature with wrong garaga_len (610 instead of 864)
        let mut signature: Array<felt252> = array![];
        let mut i: usize = 0;
        while i != 25 {
            signature.append(0);
            i += 1;
        }
        signature.append(610); // wrong garaga_len
        let _ = oauth_policy_start(signature.span());
    }
}
