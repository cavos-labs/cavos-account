/// Base64URL decoder for JWT parsing.
/// Decodes Base64URL-encoded strings (RFC 4648 §5) used in JWTs.

/// Decode a single Base64URL character to its 6-bit value.
/// Returns Option::None for invalid characters.
fn decode_char(c: u8) -> Option<u8> {
    if c >= 'A' && c <= 'Z' {
        Option::Some(c - 'A')
    } else if c >= 'a' && c <= 'z' {
        Option::Some(c - 'a' + 26)
    } else if c >= '0' && c <= '9' {
        Option::Some(c - '0' + 52)
    } else if c == '-' {
        // Base64URL uses '-' instead of '+'
        Option::Some(62)
    } else if c == '_' {
        // Base64URL uses '_' instead of '/'
        Option::Some(63)
    } else if c == '=' {
        // Padding character
        Option::Some(0)
    } else {
        Option::None
    }
}

/// Decode a Base64URL-encoded byte array.
/// Returns the decoded bytes, or panics on invalid input.
pub fn base64url_decode(input: @ByteArray, start: usize, len: usize) -> Array<u8> {
    let mut output: Array<u8> = array![];
    let mut i: usize = 0;

    while i + 3 < len {
        let a = decode_char(input.at(start + i).unwrap()).expect('invalid base64 char');
        let b = decode_char(input.at(start + i + 1).unwrap()).expect('invalid base64 char');
        let c = decode_char(input.at(start + i + 2).unwrap()).expect('invalid base64 char');
        let d = decode_char(input.at(start + i + 3).unwrap()).expect('invalid base64 char');

        // Combine 4 x 6-bit values into 3 bytes
        let combined: u32 = a.into() * 0x40000_u32
            + b.into() * 0x1000_u32
            + c.into() * 0x40_u32
            + d.into();

        output.append(((combined / 0x10000) & 0xff).try_into().unwrap());

        // Check for padding
        let char_c = input.at(start + i + 2).unwrap();
        let char_d = input.at(start + i + 3).unwrap();

        if char_c != '=' {
            output.append(((combined / 0x100) & 0xff).try_into().unwrap());
        }
        if char_d != '=' {
            output.append((combined & 0xff).try_into().unwrap());
        }

        i += 4;
    }

    // Handle remaining bytes (Base64URL may omit padding)
    let remaining = len - i;
    if remaining == 2 {
        let a = decode_char(input.at(start + i).unwrap()).expect('invalid base64 char');
        let b = decode_char(input.at(start + i + 1).unwrap()).expect('invalid base64 char');
        let combined: u32 = a.into() * 0x40_u32 + b.into();
        output.append(((combined / 0x10) & 0xff).try_into().unwrap());
    } else if remaining == 3 {
        let a = decode_char(input.at(start + i).unwrap()).expect('invalid base64 char');
        let b = decode_char(input.at(start + i + 1).unwrap()).expect('invalid base64 char');
        let c = decode_char(input.at(start + i + 2).unwrap()).expect('invalid base64 char');
        let combined: u32 = a.into() * 0x1000_u32 + b.into() * 0x40_u32 + c.into();
        output.append(((combined / 0x400) & 0xff).try_into().unwrap());
        output.append(((combined / 0x4) & 0xff).try_into().unwrap());
    }

    output
}

/// Decode only a specific window of a Base64URL-encoded byte array.
/// target_offset: The offset in the DECODED result where the desired window starts.
/// target_len: The length of the DECODED window to return.
/// This is a critical optimization for verifying claims in large JWTs without decoding the whole
/// thing.
pub fn base64url_decode_window(
    input: @ByteArray,
    segment_start: usize,
    segment_len: usize,
    target_offset: usize,
    target_len: usize,
) -> Array<u8> {
    let mut output: Array<u8> = array![];
    if target_len == 0 {
        return output;
    }

    // Each 4 Base64 chars = 3 decoded bytes
    let start_chunk = target_offset / 3;
    let end_chunk = (target_offset + target_len + 2) / 3;

    let mut chunk_idx = start_chunk;
    while chunk_idx != end_chunk {
        let i = chunk_idx * 4;
        assert!(i < segment_len, "window out of bounds");
        let remaining_chars = segment_len - i;
        if remaining_chars >= 4 {
            let a = decode_char(input.at(segment_start + i).unwrap()).expect('invalid base64 char');
            let b = decode_char(input.at(segment_start + i + 1).unwrap())
                .expect('invalid base64 char');
            let c = decode_char(input.at(segment_start + i + 2).unwrap())
                .expect('invalid base64 char');
            let d = decode_char(input.at(segment_start + i + 3).unwrap())
                .expect('invalid base64 char');

            let combined: u32 = a.into() * 0x40000_u32
                + b.into() * 0x1000_u32
                + c.into() * 0x40_u32
                + d.into();

            output.append(((combined / 0x10000) & 0xff).try_into().unwrap());
            let char_c = input.at(segment_start + i + 2).unwrap();
            let char_d = input.at(segment_start + i + 3).unwrap();
            if char_c != '=' {
                output.append(((combined / 0x100) & 0xff).try_into().unwrap());
            }
            if char_d != '=' {
                output.append((combined & 0xff).try_into().unwrap());
            }
        } else if remaining_chars == 3 {
            let a = decode_char(input.at(segment_start + i).unwrap()).expect('invalid base64 char');
            let b = decode_char(input.at(segment_start + i + 1).unwrap())
                .expect('invalid base64 char');
            let c = decode_char(input.at(segment_start + i + 2).unwrap())
                .expect('invalid base64 char');
            let combined: u32 = a.into() * 0x1000_u32 + b.into() * 0x40_u32 + c.into();
            output.append(((combined / 0x400) & 0xff).try_into().unwrap());
            output.append(((combined / 0x4) & 0xff).try_into().unwrap());
        } else if remaining_chars == 2 {
            let a = decode_char(input.at(segment_start + i).unwrap()).expect('invalid base64 char');
            let b = decode_char(input.at(segment_start + i + 1).unwrap())
                .expect('invalid base64 char');
            let combined: u32 = a.into() * 0x40_u32 + b.into();
            output.append(((combined / 0x10) & 0xff).try_into().unwrap());
        } else {
            panic!("invalid base64 length")
        }
        chunk_idx += 1;
    }

    // Slice the output to get the exact window (pointer-based, no per-element copy)
    let internal_offset = target_offset % 3;
    let output_span = output.span();
    assert!(output_span.len() >= internal_offset + target_len, "window out of bounds");
    let window = output_span.slice(internal_offset, target_len);
    let mut result: Array<u8> = array![];
    let mut remaining = window;
    while let Option::Some(val) = remaining.pop_front() {
        result.append(*val);
    }
    result
}
