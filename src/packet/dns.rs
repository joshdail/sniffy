/// Parses the DNS queries from a DNS payload (after the 12-byte DNS header).
/// Returns a vector of query domain names or an error string.
pub fn parse_dns_queries(payload: &[u8]) -> Result<Vec<String>, &'static str> {
    if payload.len() < 12 {
        return Err("DNS payload too short");
    }

    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return Ok(vec![]);
    }

    let mut queries = Vec::new();
    let mut offset = 12;

    for _ in 0..qdcount {
        let (name, next_offset) = parse_dns_name(payload, offset, 0)?;
        queries.push(name);

        // Skip QTYPE(2 bytes) + QCLASS(2 bytes)
        offset = next_offset + 4;
        if offset > payload.len() {
            break;
        }
    }

    Ok(queries)
} // parse_dns_queries

/// Parses a DNS name from the payload starting at the given offset.
/// Supports compression pointers.
///
/// `depth` tracks recursion depth to avoid infinite loops.
///
/// Returns the parsed name and the next offset after the name.
fn parse_dns_name(payload: &[u8], offset: usize, depth: usize) -> Result<(String, usize), &'static str> {
    if depth > 10 {
        return Err("Too many compression pointer indirections");
    }

    let mut labels = Vec::new();
    let mut pos = offset;

    loop {
        if pos >= payload.len() {
            return Err("Offset out of bounds during DNS name parsing");
        }

        let len = payload[pos];
        pos += 1;

        if len == 0 {
            // End of the name, return position after the zero-length label
            return Ok((labels.join("."), pos));
        }

        if (len & 0xC0) == 0xC0 {
            // Compression pointer detected
            if pos >= payload.len() {
                return Err("Incomplete compression pointer");
            }
            let b2 = payload[pos];
            pos += 1;

            // Calculate the pointer offset (14 bits)
            let pointer_offset = (((len & 0x3F) as usize) << 8) | (b2 as usize);

            if pointer_offset >= payload.len() {
                return Err("Compression pointer offset out of bounds");
            }

            // Recursively parse the name at pointer_offset
            let (ptr_name, _) = parse_dns_name(payload, pointer_offset, depth + 1)?;

            labels.push(ptr_name);

            // Return position after the pointer bytes
            return Ok((labels.join("."), pos));
        } else {
            // Regular label
            if pos + (len as usize) > payload.len() {
                return Err("Label length exceeds payload");
            }

            let label_bytes = &payload[pos..pos + (len as usize)];
            let label = std::str::from_utf8(label_bytes).map_err(|_| "Invalid UTF-8 in DNS label")?;
            labels.push(label.to_string());
            pos += len as usize;
        }
    }
} // parse_dns_name
