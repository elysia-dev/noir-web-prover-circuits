use crate::language::{TEST_DATA_BYTES, TEST_MAX_STACK_HEIGHT, TEST_PUBLIC_IO_LENGTH};
use crate::utils::{
    compress_tree_hash, create_nested_object_key_sequence_with_tree_hasher, create_value_digest,
    polynomial_digest, polynomial_digest_with_counter,
};
use crate::extractor::{ExtractorState};
#[test]
fn test_extract_with_padding() {
    // Test with all padding bytes (255)
    let data: [u8; TEST_DATA_BYTES] = [255; TEST_DATA_BYTES];
    let ciphertext_digest = 1;
    let sequence_digest = 0;
    let value_digest = 0;
    let state = [0; TEST_MAX_STACK_HEIGHT * 4 + 4];
    let step_in: [Field; TEST_PUBLIC_IO_LENGTH] = [0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0];

    let extractor = ExtractorState::<TEST_DATA_BYTES, TEST_MAX_STACK_HEIGHT, TEST_PUBLIC_IO_LENGTH> {
        data,
        ciphertext_digest,
        sequence_digest,
        value_digest,
        state,
    };

    let step_out = extractor.extract(step_in);

    // Verify output matches expected values
    assert(step_out[0] == 0);
    assert(step_out[7] == step_in[7]);
    assert(step_out[8] == 0);
    for i in 1..TEST_PUBLIC_IO_LENGTH {
        if (i != 7) & (i != 8) {
            assert(step_out[i] == step_in[i]);
        }
    }
}

#[test]
fn test_extract_nested_object() {
    // Test with nested JSON object: {"outer":{"inner":"value"}}
    let mut data: [u8; TEST_DATA_BYTES] = [0; TEST_DATA_BYTES];
    // {"outer":{"inner":"value"}}
    let json_bytes = [
        123, 34, 111, 117, 116, 101, 114, 34, 58, 123, 34, 105, 110, 110, 101, 114, 34, 58, 34, 118,
        97, 108, 117, 101, 34, 125, 125,
    ];

    for i in 0..json_bytes.len() {
        data[i] = json_bytes[i];
    }
    for i in json_bytes.len()..TEST_DATA_BYTES {
        data[i] = 255; // Padding
    }

    let ciphertext_digest = 1;
    let mut monomials = [0; 3 * TEST_MAX_STACK_HEIGHT];
    monomials[0] = 1;
    for i in 1..3 * TEST_MAX_STACK_HEIGHT {
        monomials[i] = monomials[i - 1] * ciphertext_digest;
    }

    // Create key sequence for "outer.inner" path
    let outer_key_bytes = [111, 117, 116, 101, 114]; // "outer"
    let inner_key_bytes = [105, 110, 110, 101, 114]; // "inner"

    // Use nested object key sequence helper
    let sequence_digest = create_nested_object_key_sequence_with_tree_hasher::<TEST_MAX_STACK_HEIGHT, TEST_DATA_BYTES>(
        outer_key_bytes,
        inner_key_bytes,
        ciphertext_digest,
        monomials,
    );
    // Value digest for "value"
    let value_bytes = [118, 97, 108, 117, 101]; // "value"
    let value_digest = create_value_digest(value_bytes, ciphertext_digest);

    let state = [0; TEST_MAX_STACK_HEIGHT * 4 + 4];

    // Calculate data digest
    let mut zeroed_data: [Field; TEST_DATA_BYTES] = [0; TEST_DATA_BYTES];
    for i in 0..TEST_DATA_BYTES {
        let is_padding = if data[i] == 255 { 1 } else { 0 };
        zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
    }
    let step_in_7 = 1;
    let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

    let step_in: [Field; TEST_PUBLIC_IO_LENGTH] = [data_digest, 1, 1, 0, 0, 0, 0, step_in_7, 0, 0, 0];

    let extractor = ExtractorState::<TEST_DATA_BYTES, TEST_MAX_STACK_HEIGHT, TEST_PUBLIC_IO_LENGTH> {
        data,
        ciphertext_digest,
        sequence_digest,
        value_digest,
        state,
    };
    let step_out = extractor.extract(step_in);

    // Verify output
    assert(step_out[0] == value_digest);
    assert(step_out[7] == ciphertext_digest.pow_32(json_bytes.len() as Field));
}

// #[test]
// fn test_extract_nested_object_with_different_digest() {
//     // Test with nested JSON object: {"outer":{"inner":"value"}}
//     let mut data: [u8; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     // {"outer":{"inner":"value"}}
//     let json_bytes = [
//         123, 34, 111, 117, 116, 101, 114, 34, 58, 123, 34, 105, 110, 110, 101, 114, 34, 58, 34, 118,
//         97, 108, 117, 101, 34, 125, 125,
//     ];

//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }
//     for i in json_bytes.len()..TEST_DATA_BYTES {
//         data[i] = 255; // Padding
//     }

//     // Use a different ciphertext_digest value
//     let ciphertext_digest = 10;

//     let mut monomials: [Field; 3 * TEST_MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * TEST_MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     // Create key sequence for "outer.inner" path
//     let outer_key_bytes = [111, 117, 116, 101, 114]; // "outer"
//     let inner_key_bytes = [105, 110, 110, 101, 114]; // "inner"

//     // Use nested object key sequence helper
//     let sequence_digest = create_nested_object_key_sequence_with_tree_hasher(
//         outer_key_bytes,
//         inner_key_bytes,
//         ciphertext_digest,
//         monomials,
//     );

//     // Value digest for "value"
//     let value_bytes = [118, 97, 108, 117, 101]; // "value"
//     let value_digest = create_value_digest(value_bytes, ciphertext_digest);

//     let state: [Field; TEST_MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     // Calculate data digest
//     let mut zeroed_data: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..TEST_DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let step_in: [Field; TEST_PUBLIC_IO_LENGTH] = [data_digest, 1, 1, 0, 0, 0, 0, step_in_7, 0, 0, 0];

//     let extractor = ExtractorState::<TEST_DATA_BYTES, TEST_MAX_STACK_HEIGHT, TEST_PUBLIC_IO_LENGTH> {
//         data,
//         ciphertext_digest,
//         sequence_digest,
//         value_digest,
//         state,
//     };

//     let step_out = extractor.extract(step_in);

//     // Verify output
//     assert(step_out[0] == value_digest);
//     assert(step_out[7] == ciphertext_digest.pow_32(json_bytes.len() as Field));
// }

// #[test]
// fn test_extract_array_element() {
//     let json_bytes = [
//         91, 52, 50, 44, 123, 34, 97, 34, 58, 34, 98, 34, 125, 44, 34, 99, 34,
//         93, // [42,{"a":"b"},"c"]
//     ];

//     let mut data: [u8; TEST_DATA_BYTES] = [255; DATA_BYTES];
//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }

//     let ciphertext_digest = 7;

//     let mut monomials: [Field; 3 * TEST_MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * TEST_MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     let mut key_value: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     let key = JsonMaskType { is_array_index: true, value: key_value, array_index: 0 };
//     let key_sequence = [key];

//     let (stack, tree_hashes) = json_tree_hasher(ciphertext_digest, key_sequence);

//     let sequence_digest = compress_tree_hash(stack, tree_hashes, monomials);

//     let value_bytes = [52, 50]; // "42"
//     let value_digest = create_value_digest(value_bytes, ciphertext_digest);

//     let state: [Field; TEST_MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     let mut zeroed_data: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..TEST_DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let sequence_digest_hashed = sequence_digest;

//     let step_in: [Field; TEST_PUBLIC_IO_LENGTH] =
//         [data_digest, 0, 0, 0, 0, 0, 0, step_in_7, 0, sequence_digest_hashed, 0];

//     let extractor = ExtractorState::<TEST_DATA_BYTES, TEST_MAX_STACK_HEIGHT, TEST_PUBLIC_IO_LENGTH> {
//         data,
//         ciphertext_digest,
//         sequence_digest,
//         value_digest,
//         state,
//     };

//     let step_out = extractor.extract(step_in);

//     assert(step_out[0] == value_digest);
//     assert(step_out[7] == ciphertext_digest.pow_32(json_bytes.len() as Field));
//     assert(step_out[9] == sequence_digest_hashed);
// }

// #[test]
// fn test_extract_object_array_value() {
//     let json_bytes = [
//         123, 34, 107, 34, 58, 91, 52, 50, 48, 44, 54, 57, 93, 44, 34, 98, 34, 58, 91, 34, 97, 34,
//         44, 34, 98, 34, 44, 34, 99, 34, 44, 34, 100, 34, 93, 125,
//     ];

//     let mut data: [u8; TEST_DATA_BYTES] = [255; DATA_BYTES];
//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }

//     let ciphertext_digest = 7;

//     let mut monomials: [Field; 3 * TEST_MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * TEST_MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     let mut key1_value: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     key1_value[0] = Field::from(98); // "b"

//     let key1 = JsonMaskType { is_array_index: false, value: key1_value, array_index: 0 };
//     let key2 = JsonMaskType { is_array_index: true, value: [0; TEST_DATA_BYTES], array_index: 3 };

//     let key_sequence = [key1, key2];

//     let (stack, tree_hashes) = json_tree_hasher(ciphertext_digest, key_sequence);

//     let sequence_digest = compress_tree_hash(stack, tree_hashes, monomials);

//     let value_bytes = [100]; // "d"
//     let value_digest = create_value_digest(value_bytes, ciphertext_digest);

//     let state: [Field; TEST_MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     let mut zeroed_data: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..TEST_DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let step_in: [Field; TEST_PUBLIC_IO_LENGTH] =
//         [data_digest, 0, 0, 0, 0, 0, 0, step_in_7, 0, sequence_digest, 0];

//     let extractor = ExtractorState::<TEST_DATA_BYTES, TEST_MAX_STACK_HEIGHT, TEST_PUBLIC_IO_LENGTH> {
//         data,
//         ciphertext_digest,
//         sequence_digest,
//         value_digest,
//         state,
//     };

//     let step_out = extractor.extract(step_in);

//     assert(step_out[0] == value_digest);
//     assert(step_out[7] == ciphertext_digest.pow_32(json_bytes.len() as Field));
//     assert(step_out[9] == sequence_digest);
// }

// #[test]
// fn test_extract_primitive_values() {
//     let json_bytes = [
//         123, 34, 110, 117, 108, 108, 34, 58, 110, 117, 108, 108, 44, 34, 116, 114, 117, 101, 34, 58,
//         116, 114, 117, 101, 44, 34, 102, 97, 108, 115, 101, 34, 58, 102, 97, 108, 115, 101, 44, 34,
//         110, 117, 109, 49, 34, 58, 48, 46, 50, 44, 34, 110, 117, 109, 50, 34, 58, 50, 48, 125,
//     ];

//     let mut data: [u8; TEST_DATA_BYTES] = [255; DATA_BYTES];
//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }

//     let ciphertext_digest = 7;

//     let mut monomials: [Field; 3 * TEST_MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * TEST_MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     let mut key_value: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     let true_key = [116, 114, 117, 101];
//     for i in 0..true_key.len() {
//         key_value[i] = Field::from(true_key[i]);
//     }

//     let key = JsonMaskType { is_array_index: false, value: key_value, array_index: 0 };
//     let key_sequence = [key];

//     let (stack, tree_hashes) = json_tree_hasher(ciphertext_digest, key_sequence);

//     let sequence_digest = compress_tree_hash(stack, tree_hashes, monomials);

//     let value_bytes = [116, 114, 117, 101];
//     let value_digest = create_value_digest(value_bytes, ciphertext_digest);

//     let state: [Field; TEST_MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     let mut zeroed_data: [Field; TEST_DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..TEST_DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let sequence_digest_hashed = sequence_digest;

//     let step_in: [Field; TEST_PUBLIC_IO_LENGTH] =
//         [data_digest, 0, 0, 0, 0, 0, 0, step_in_7, 0, sequence_digest_hashed, 0];

//     let step_out = extract(
//         data,
//         ciphertext_digest,
//         sequence_digest,
//         value_digest,
//         state,
//         step_in,
//     );

//     assert(step_out[0] == value_digest);
//     assert(step_out[7] == ciphertext_digest.pow_32(json_bytes.len() as Field));
//     assert(step_out[9] == sequence_digest_hashed);
// }
