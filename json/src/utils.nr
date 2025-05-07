/// Returns true if `a` and `b` are equal, false otherwise.
pub fn is_equal(a: u8, b: u8) -> bool {
    a == b
}

/// Returns true if `a` is zero, false otherwise.
pub fn is_zero(a: u8) -> bool {
    a == 0
}

/// Returns true if `value` exists in the given array, false otherwise
pub fn contains<let N: u32>(value: u8, array: [u8; N]) -> bool {
    array.any(|x| x == value)
}

/// Computes a polynomial hash digest of the input array `bytes` using the given `polynomial_input` as the base.
/// The digest is calculated as: bytes[0] + bytes[1]*polynomial_input + bytes[2]*polynomial_input^2 + ..

pub fn polynomial_digest<let DATA_BYTES: u32>(
    bytes: [Field; DATA_BYTES],
    polynomial_input: Field,
) -> Field {
    let mut digest = 0;
    let mut monomial = 1;
    for i in 0..DATA_BYTES {
        digest += bytes[i] * monomial;
        monomial *= polynomial_input;
    }
    digest
}

/// Computes a polynomial hash digest of the input array `bytes` using the given `polynomial_input` as the base,
/// starting with an initial power `pow_ctr` instead of 1.
pub fn polynomial_digest_with_counter<let DATA_BYTES: u32>(
    bytes: [Field; DATA_BYTES],
    polynomial_input: Field,
    pow_ctr: Field,
) -> Field {
    let mut digest = 0;
    let mut monomial = pow_ctr;
    for i in 0..DATA_BYTES {
        digest += bytes[i] * monomial;
        monomial *= polynomial_input;
    }
    digest
}

/// Represents a mask type for JSON tree hashing.
/// - `is_array_index`: true if this mask is for an array index, false for an object key.
/// - `value`: the key value as a 32-byte field array.
/// - `array_index`: the index if this is an array element.

pub struct JsonMaskType<let DATA_BYTES: u32> {
    pub is_array_index: bool,
    pub value: [Field; DATA_BYTES],
    pub array_index: u32,
}

/// returns stack and tree hashes
pub fn json_tree_hasher<let DATA_BYTES: u32, let MAX_STACK_HEIGHT: u32>(
    ct_digest: Field,
    key_sequence: [JsonMaskType<DATA_BYTES>; DATA_BYTES],
) -> ([[Field; 2]; MAX_STACK_HEIGHT], [[Field; 2]; MAX_STACK_HEIGHT]) {
    let mut stack: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];
    let mut tree_hashes: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];

    stack[0][0] = 1;

    for i in 0..MAX_STACK_HEIGHT {
        let key = key_sequence[i];

        if !key.is_array_index {
            stack[i] = [1, 1];
            let mut key_digest = 0;
            let mut monomial = 1;
            for i in 0..DATA_BYTES {
                key_digest += key.value[i] * monomial;
                monomial *= ct_digest;
            }
            tree_hashes[i][0] = key_digest;
        } else {
            tree_hashes[i][0] = 0;
            stack[i] = [2 as Field, key.array_index as Field];
        }
    }

    (stack, tree_hashes)
}

pub fn compress_tree_hash<let MAX_STACK_HEIGHT: u32>(
    stack: [[Field; 2]; MAX_STACK_HEIGHT],
    tree_hashes: [[Field; 2]; MAX_STACK_HEIGHT],
    monomials: [Field; 3 * MAX_STACK_HEIGHT],
) -> Field {
    let mut accumulator = 0;
    for i in 0..MAX_STACK_HEIGHT {
        accumulator += stack[i][0] * monomials[3 * i];
        accumulator += stack[i][1] * monomials[3 * i + 1];
        accumulator += tree_hashes[i][0] * monomials[3 * i + 2];
    }

    accumulator
}

// Create a digest for a value (string, number, etc.)
pub fn create_value_digest(value_bytes: [u8], ciphertext_digest: Field) -> Field {
    let mut result = 0;
    let mut monomial = 1;

    for i in 0..value_bytes.len() {
        result += Field::from(value_bytes[i]) * monomial;
        monomial *= ciphertext_digest;
    }

    result
}

// Create a sequence digest for a simple object key
pub fn create_object_key_sequence(key_bytes: [u8], ciphertext_digest: Field) -> Field {
    // Create stack entry for object key [1, 0]
    let stack_entry: [Field; 2] = [1, 0];
    // Create tree hash for the key
    let key_hash = create_value_digest(key_bytes, ciphertext_digest);

    // Compress the tree hash
    let mut result = 0;
    let mut monomial = 1;

    // Add stack entry with appropriate monomials
    result += stack_entry[0] * monomial;
    monomial *= ciphertext_digest;
    result += stack_entry[1] * monomial;
    monomial *= ciphertext_digest;

    // Add key hash
    result += key_hash * monomial;

    result
}

// only for testing
// Create a sequence digest for a nested object path (e.g., obj.nested)
pub fn create_nested_object_key_sequence_with_tree_hasher<let MAX_STACK_HEIGHT: u32, let DATA_BYTES: u32>(
    key1_bytes: [u8],
    key2_bytes: [u8],
    ciphertext_digest: Field,
    monomials: [Field; 3 * MAX_STACK_HEIGHT],
) -> Field {
    // Convert key bytes to JsonMaskType format
    let mut key1_value: [Field; DATA_BYTES] = [0; DATA_BYTES];
    let mut key2_value: [Field; DATA_BYTES] = [0; DATA_BYTES];

    for i in 0..key1_bytes.len() {
        key1_value[i] = Field::from(key1_bytes[i]);
    }

    for i in 0..key2_bytes.len() {
        key2_value[i] = Field::from(key2_bytes[i]);
    }

    let key1: JsonMaskType<DATA_BYTES> =
        JsonMaskType { is_array_index: false, value: key1_value, array_index: 0 };
    let key2: JsonMaskType<DATA_BYTES> =
        JsonMaskType { is_array_index: false, value: key2_value, array_index: 0 };

    // Create key sequence with length DATA_BYTES
    let default_key: JsonMaskType<DATA_BYTES> =
        JsonMaskType { is_array_index: false, value: [0; DATA_BYTES], array_index: 0 };
    let mut key_sequence: [JsonMaskType<DATA_BYTES>; DATA_BYTES] = [default_key; DATA_BYTES];
    key_sequence[0] = key1;
    key_sequence[1] = key2;

    let (stack, tree_hashes) =
        json_tree_hasher::<DATA_BYTES, MAX_STACK_HEIGHT>(ciphertext_digest, key_sequence);

    // Use compress_tree_hash to get the sequence digest
    compress_tree_hash(stack, tree_hashes, monomials)
}
