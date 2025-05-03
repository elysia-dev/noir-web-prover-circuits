use crate::language::{DATA_BYTES, MAX_STACK_HEIGHT};

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
pub fn polynomial_digest(bytes: [Field; DATA_BYTES], polynomial_input: Field) -> Field {
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
pub fn polynomial_digest_with_counter(
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
pub struct JsonMaskType {
    pub is_array_index: bool,
    pub value: [Field; 32],
    pub array_index: u32,
}

pub fn json_tree_hasher<let N: u32>(
    ct_digest: Field,
    key_sequence: [JsonMaskType; N],
    max_stack_height: u32,
) -> ([[Field; 2]; MAX_STACK_HEIGHT], [[Field; 2]; MAX_STACK_HEIGHT]) {
    let mut stack: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];
    let mut tree_hashes: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];

    stack[0][0] = 1;

    for i in 0..N {
        let key = key_sequence[i];

        if key.is_array_index {
            let array_index = key.array_index;
            let index_hash = Field::from(array_index);

            let curr_hash = index_hash * ct_digest + tree_hashes[0][1];
            tree_hashes[0][1] = curr_hash;
        } else {
            let key_bytes = key.value;
            let key_digest = polynomial_digest(key_bytes, ct_digest);
            let curr_hash = key_digest * ct_digest + tree_hashes[0][1];
            tree_hashes[0][1] = curr_hash;
        }

        if i < N - 1 {
            for j in 1..max_stack_height {
                stack[j] = stack[j - 1];
                tree_hashes[j] = tree_hashes[j - 1];
            }
            stack[0] = [1, 0];
            tree_hashes[0] = [0, 0];
        }
    }

    (stack, tree_hashes)
}

pub fn compress_tree_hash(
    ct_digest: Field,
    stack: [[Field; 2]; MAX_STACK_HEIGHT],
    tree_hashes: [[Field; 2]; MAX_STACK_HEIGHT],
) -> Field {
    let mut accumulator = 0;
    let mut monomial = 1;

    for i in 0..MAX_STACK_HEIGHT {
        accumulator += stack[i][0] * monomial;
        monomial *= ct_digest;
        accumulator += stack[i][1] * monomial;
        monomial *= ct_digest;
        accumulator += tree_hashes[i][0] * monomial;
        monomial *= ct_digest;
        accumulator += tree_hashes[i][1] * monomial;
        monomial *= ct_digest;
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

// Create a sequence digest for a nested object path (e.g., obj.nested)
pub fn create_nested_object_key_sequence(
    key1_bytes: [u8],
    key2_bytes: [u8],
    ciphertext_digest: Field,
) -> Field {
    // First create object entry for first key
    let obj_digest = create_object_key_sequence(key1_bytes, ciphertext_digest);

    // Then create object entry for second key, with first key as parent
    let stack_entry: [Field; 2] = [1, 0];

    // Create tree hash for the second key
    let key2_hash = create_value_digest(key2_bytes, ciphertext_digest);

    // Compress the tree hash
    let mut result = obj_digest;
    let mut monomial = ciphertext_digest.pow_32(3);

    // Add stack entry with appropriate monomials
    result += stack_entry[0] * monomial;
    monomial *= ciphertext_digest;
    result += stack_entry[1] * monomial;
    monomial *= ciphertext_digest;

    // Add key hash
    result += key2_hash * monomial;

    result
}

pub fn create_array_index_sequence(index: u64, ciphertext_digest: Field) -> Field {
    // Create stack entry for array index [2, index]
    let stack_entry: [Field; 2] = [2, index as Field];

    // Compress the tree hash
    let mut result = 0;
    let mut monomial = 1;

    // Add stack entry with appropriate monomials
    result += stack_entry[0] * monomial;
    monomial *= ciphertext_digest;
    result += stack_entry[1] * monomial;

    result
}

pub fn create_object_array_sequence(
    key_bytes: [u8],
    index: u64,
    ciphertext_digest: Field,
) -> Field {
    // First create object entry for the key
    let obj_digest = create_object_key_sequence(key_bytes, ciphertext_digest);

    // Then create array entry for the index
    let stack_entry: [Field; 2] = [2, index as Field];

    // Compress the tree hash
    let mut result = obj_digest;
    let mut monomial = ciphertext_digest.pow_32(3); // Skip 3 monomials used by key

    // Add stack entry with appropriate monomials
    result += stack_entry[0] * monomial;
    monomial *= ciphertext_digest;
    result += stack_entry[1] * monomial;

    result
}
