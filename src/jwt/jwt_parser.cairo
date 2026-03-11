/// JWT parser for extracting claims from Google/Apple JWTs.
/// Parses the payload to extract `sub`, `nonce`, `exp`, and `kid` from header.
///
/// Note: Full JSON parsing in Cairo is expensive. Instead, we use a simplified
/// approach where the SDK pre-parses the JWT and passes structured data.
/// The contract verifies the RSA signature on the raw JWT bytes, ensuring
/// the pre-parsed data matches.

/// Parsed JWT data passed from the SDK.
/// The SDK pre-parses the JWT and provides structured fields.
/// The contract verifies the RSA signature on the original JWT to ensure integrity.
use core::poseidon::poseidon_hash_span;

#[derive(Copy, Drop, Serde)]
pub struct JWTData {
    /// The `sub` claim (Google/Apple user ID) as felt252
    pub sub: felt252,
    /// The `nonce` claim as felt252
    pub nonce: felt252,
    /// The `exp` claim (expiration timestamp)
    pub exp: u64,
    /// The full-string `kid` (key ID) from the JWT header, hashed into a felt252
    pub kid: felt252,
    /// The `iss` (issuer) claim as felt252 hash
    pub iss: felt252,
    /// The `aud` (audience / app_id) claim as felt252 hash
    pub aud: felt252,
}

/// Find the index of a byte in a ByteArray, starting from a given offset.
pub fn find_byte(data: @ByteArray, byte: u8, from: usize) -> Option<usize> {
    let len = data.len();
    let mut i = from;
    loop {
        if i >= len {
            break Option::None;
        }
        if data.at(i).unwrap() == byte {
            break Option::Some(i);
        }
        i += 1;
    }
}

/// Split JWT into header, payload, and signature parts by finding '.' delimiters.
/// Returns (header_end, payload_start, payload_end, sig_start) indices.
pub fn split_jwt(jwt_bytes: @ByteArray) -> (usize, usize, usize, usize) {
    let dot1 = find_byte(jwt_bytes, '.', 0).expect('JWT missing first dot');
    let dot2 = find_byte(jwt_bytes, '.', dot1 + 1).expect('JWT missing second dot');
    (dot1, dot1 + 1, dot2, dot2 + 1)
}

/// Split just the signed portion of a JWT (header.payload) into header and payload parts.
/// Returns (header_end, payload_start, payload_end) indices.
pub fn split_signed_data(signed_bytes: @ByteArray) -> (usize, usize, usize) {
    let dot1 = find_byte(signed_bytes, '.', 0).expect('Signed data missing dot');
    (dot1, dot1 + 1, signed_bytes.len())
}

fn trim_leading_ascii_zeros(data: Span<u8>) -> Span<u8> {
    let len = data.len();
    let mut first_non_zero: usize = 0;
    while first_non_zero < len && *data[first_non_zero] == 48 {
        first_non_zero += 1;
    }
    data.slice(first_non_zero, len - first_non_zero)
}

fn parse_hex_digit(byte: u8) -> u8 {
    if byte >= 48 && byte <= 57 {
        byte - 48
    } else if byte >= 97 && byte <= 102 {
        byte - 87
    } else if byte >= 65 && byte <= 70 {
        byte - 55
    } else {
        panic!("Not a hex digit")
    }
}

fn assert_decimal_within_felt_range(data: Span<u8>) {
    let trimmed = trim_leading_ascii_zeros(data);
    let trimmed_len = trimmed.len();
    if trimmed_len == 0 {
        return;
    }

    let max_decimal: ByteArray =
        "3618502788666131213697322783095070105623107215331596699973092056135872020480";
    assert!(trimmed_len <= max_decimal.len(), "Decimal overflow");
    if trimmed_len < max_decimal.len() {
        return;
    }

    let mut i: usize = 0;
    while i < trimmed_len {
        let digit = *trimmed[i];
        let max_digit = max_decimal.at(i).unwrap();
        if digit < max_digit {
            return;
        }
        assert!(digit == max_digit, "Decimal overflow");
        i += 1;
    }
}

fn assert_hex_within_felt_range(data: Span<u8>) {
    let trimmed = trim_leading_ascii_zeros(data);
    let trimmed_len = trimmed.len();
    if trimmed_len == 0 {
        return;
    }

    let max_hex: ByteArray = "800000000000011000000000000000000000000000000000000000000000000";
    assert!(trimmed_len <= max_hex.len(), "Hex overflow");
    if trimmed_len < max_hex.len() {
        return;
    }

    let mut i: usize = 0;
    while i < trimmed_len {
        let digit = parse_hex_digit(*trimmed[i]);
        let max_digit = parse_hex_digit(max_hex.at(i).unwrap());
        if digit < max_digit {
            return;
        }
        assert!(digit == max_digit, "Hex overflow");
        i += 1;
    }
}

pub fn hash_utf8_bytes(data: Span<u8>) -> felt252 {
    let mut value: ByteArray = "";
    let mut remaining = data;
    while let Option::Some(byte_ref) = remaining.pop_front() {
        value.append_byte(*byte_ref);
    }

    let mut serialized: Array<felt252> = array![];
    value.serialize(ref serialized);
    poseidon_hash_span(serialized.span())
}

/// Parse a decimal string (ASCII bytes) to a felt252.
pub fn parse_decimal(data: Span<u8>) -> felt252 {
    assert_decimal_within_felt_range(data);

    let mut result: felt252 = 0;
    let mut remaining = data;
    while let Option::Some(byte) = remaining.pop_front() {
        let b = *byte;
        assert!(b >= 48 && b <= 57, "Not a decimal digit");
        result = result * 10 + (b - 48).into();
    }
    result
}

/// Parse a hex string (ASCII bytes, optionally starting with 0x) to a felt252.
pub fn parse_hex(data: Span<u8>) -> felt252 {
    let mut result: felt252 = 0;

    // Skip 0x prefix if present, using slice for pointer-based skip
    let mut remaining = if data.len() >= 2
        && *data[0] == 48
        && (*data[1] == 120 || *data[1] == 88) {
        data.slice(2, data.len() - 2)
    } else {
        data
    };

    assert_hex_within_felt_range(remaining);

    while let Option::Some(byte_ref) = remaining.pop_front() {
        let byte = *byte_ref;
        let val = parse_hex_digit(byte);
        result = result * 16 + val.into();
    }
    result
}
