use crate::language::{DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH};
use crate::machine::{state_update_hasher, StateUpdateHasherInput};
use crate::utils::{
    compress_tree_hash, create_nested_object_key_sequence_with_tree_hasher, create_value_digest,
    json_tree_hasher, JsonMaskType, polynomial_digest, polynomial_digest_with_counter,
};

pub struct ExtractorState<let DATA_BYTES: u32, let MAX_STACK_HEIGHT: u32, let PUBLIC_IO_LENGTH: u32> {
    data: [u8; DATA_BYTES],
    ciphertext_digest: Field,
    sequence_digest: Field,
    value_digest: Field,
    state: [Field; MAX_STACK_HEIGHT * 4 + 4],
}

// It processes JSON data byte-by-byte to find and extract specific values
/// - `data`: The JSON data bytes to process
/// - `ciphertext_digest`: Base value for polynomial digests
/// - `sequence_digest`: Digest of the key sequence (path) to the target value
/// - `value_digest`: Digest of the expected value to extract
/// - `state`: Initial parser state
/// - `step_in`: Input step variables from previous circuit
impl<let DATA_BYTES: u32, let MAX_STACK_HEIGHT: u32, let PUBLIC_IO_LENGTH: u32> ExtractorState<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH> {
    // It processes JSON data byte-by-byte to find and extract specific values
    pub fn extract(self, step_in: [Field; PUBLIC_IO_LENGTH]) -> [Field; PUBLIC_IO_LENGTH] {
        // Verify input state digest matches expected value
        let input_state_digest = polynomial_digest(self.state, self.ciphertext_digest);
        assert(step_in[8] == input_state_digest);

        // Initialize monomials for polynomial digests
        // These are used to calculate state digests efficiently
        let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
        monomials[0] = 1;
        for i in 1..3 * MAX_STACK_HEIGHT {
            monomials[i] = monomials[i - 1] * self.ciphertext_digest;
        }

        // Initialize state tracking variables
        let mut state_digest: [Field; DATA_BYTES] = [0; DATA_BYTES];
        let mut sequence_is_matched: [Field; DATA_BYTES] = [0; DATA_BYTES];
        let mut value_is_matched: [Field; DATA_BYTES] = [0; DATA_BYTES];
        let mut total_matches = 0;

        // Initialize parser state from input state
        let mut prev_stack: [[Field; 2]; MAX_STACK_HEIGHT] =
            [[Field::from(0); 2]; MAX_STACK_HEIGHT];
        let mut prev_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT] =
            [[Field::from(0); 2]; MAX_STACK_HEIGHT];
        let mut prev_monomial = self.state[MAX_STACK_HEIGHT * 4];
        let mut prev_parsing_string = self.state[MAX_STACK_HEIGHT * 4 + 1] != 0;
        let mut prev_parsing_primitive = self.state[MAX_STACK_HEIGHT * 4 + 2] != 0;
        let mut prev_escaped = self.state[MAX_STACK_HEIGHT * 4 + 3] != 0;

        for i in 0..MAX_STACK_HEIGHT {
            prev_stack[i] = [self.state[i * 2], self.state[i * 2 + 1]];
            prev_tree_hash[i] = [
                self.state[MAX_STACK_HEIGHT * 2 + i * 2],
                self.state[MAX_STACK_HEIGHT * 2 + i * 2 + 1],
            ];
        }

        // Process each byte of input data
        for data_idx in 0..DATA_BYTES {
            // Create state update input
            let update_input = StateUpdateHasherInput {
                byte: self.data[data_idx],
                stack: prev_stack,
                tree_hash: prev_tree_hash,
                parsing_string: prev_parsing_string,
                parsing_primitive: prev_parsing_primitive,
                polynomial_input: self.ciphertext_digest,
                monomial: prev_monomial,
                escaped: prev_escaped,
            };

            // Update state based on current byte
            let update_output = state_update_hasher(update_input);

            // Update state for next iteration
            prev_stack = update_output.next_stack;
            prev_tree_hash = update_output.next_tree_hash;
            prev_monomial = update_output.next_monomial;
            prev_parsing_string = update_output.next_parsing_string;
            prev_parsing_primitive = update_output.next_parsing_primitive;
            prev_escaped = update_output.next_escaped;

            // Calculate state digest
            state_digest[data_idx] = compress_tree_hash(prev_stack, prev_tree_hash, monomials);

            // Check if sequence matches
            sequence_is_matched[data_idx] = if state_digest[data_idx] == self.sequence_digest {
                1
            } else {
                0
            };

            let mut tmp_sequence_matched = sequence_is_matched[data_idx];
            //println(f"sequence_digest: {self.sequence_digest}");
            println(f"sequence_matched: {tmp_sequence_matched}");

            // Check if value matches
            let mut value_digest_in_stack = Field::from(0);
            for i in 0..MAX_STACK_HEIGHT {
                value_digest_in_stack += prev_tree_hash[i][1];
            }
            value_is_matched[data_idx] = if self.value_digest == value_digest_in_stack {
                1
            } else {
                0
            };

            // println(f"value_digest_in_stack: {value_digest_in_stack}");
            // println(f"value_digest: {self.value_digest}");
            let mut tmp2 = value_is_matched[data_idx];
            println(f"value_matched: {tmp2}");

            // Update total matches
            let matched = sequence_is_matched[data_idx] * value_is_matched[data_idx];
            total_matches += matched;
            println(f"total_matches updated: {total_matches}");
        }

        // Create new state from final parser state
        let mut new_state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];
        for i in 0..MAX_STACK_HEIGHT {
            new_state[i * 2] = prev_stack[i][0];
            new_state[i * 2 + 1] = prev_stack[i][1];
            new_state[MAX_STACK_HEIGHT * 2 + i * 2] = prev_tree_hash[i][0];
            new_state[MAX_STACK_HEIGHT * 2 + i * 2 + 1] = prev_tree_hash[i][1];
        }
        new_state[MAX_STACK_HEIGHT * 4] = prev_monomial;
        new_state[MAX_STACK_HEIGHT * 4 + 1] = if prev_parsing_string { 1 } else { 0 };
        new_state[MAX_STACK_HEIGHT * 4 + 2] = if prev_parsing_primitive { 1 } else { 0 };
        new_state[MAX_STACK_HEIGHT * 4 + 3] = if prev_escaped { 1 } else { 0 };

        // Check if all data is padding (255)
        let mut all_padding = true;
        for i in 0..DATA_BYTES {
            all_padding = all_padding & (self.data[i] == 255);
        }

        // If all bytes are padding, set digest to 0, otherwise calculate normally
        let new_state_digest = if all_padding {
            0
        } else {
            polynomial_digest(new_state, self.ciphertext_digest)
        };

        // Calculate ciphertext digest powers and handle padding
        let mut ciphertext_digest_pow: [Field; DATA_BYTES + 1] = [0; DATA_BYTES + 1];
        ciphertext_digest_pow[0] = step_in[7];
        let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];
        for i in 0..DATA_BYTES {
            let is_padding = if self.data[i] == 255 { 1 } else { 0 };
            zeroed_data[i] = (1 - is_padding) * Field::from(self.data[i]);
            let mult_factor = (1 - is_padding) * self.ciphertext_digest + is_padding;
            ciphertext_digest_pow[i + 1] = ciphertext_digest_pow[i] * mult_factor;
        }
        let data_digest =
            polynomial_digest_with_counter(zeroed_data, self.ciphertext_digest, step_in[7]);

        // Prepare output
        let mut step_out: [Field; PUBLIC_IO_LENGTH] = [0; PUBLIC_IO_LENGTH];
        step_out[0] = step_in[0] - data_digest + self.value_digest * total_matches;
        step_out[1] = step_in[1];
        step_out[2] = step_in[2];
        step_out[3] = step_in[3];
        step_out[4] = step_in[4];
        step_out[5] = step_in[5];
        step_out[6] = step_in[6];
        step_out[7] = ciphertext_digest_pow[DATA_BYTES];
        step_out[8] = new_state_digest;
        step_out[9] = step_in[9];
        step_out[10] = step_in[10];

        // Verify output consistency
        assert(step_out[1] == step_out[2]);
        let is_value_digest_zero = (self.value_digest == 0) as u8;
        let is_new_state_digest_zero = (new_state_digest == 0) as u8;
        let is_step_out_zero_matched = (step_out[0] == self.value_digest) as u8;

        assert(
            (1 - is_value_digest_zero) * (is_new_state_digest_zero - is_step_out_zero_matched) == 0,
        );

        let mut temp = step_out[0];
        let mut temp_value_digest = self.value_digest;
        let mut temp_sequence_digest = self.sequence_digest;
        println(f"step_out[0]: {temp}");
        println(f"value_digest: {temp_value_digest}");
        println(f"total_matches: {total_matches}");
        println(f"sequence_digest: {temp_sequence_digest}");
        println(f"data_digest: {data_digest}");

        step_out
    }
}

#[test]
fn test_extract_with_padding() {
    // Test with all padding bytes (255)
    let data: [u8; DATA_BYTES] = [255; DATA_BYTES];
    let ciphertext_digest = 1;
    let sequence_digest = 0;
    let value_digest = 0;
    let state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];
    let step_in: [Field; PUBLIC_IO_LENGTH] = [0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0];

    let extractor = ExtractorState::<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH> {
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
    for i in 1..PUBLIC_IO_LENGTH {
        if (i != 7) & (i != 8) {
            assert(step_out[i] == step_in[i]);
        }
    }
}

#[test]
fn test_extract_nested_object() {
    // Test with nested JSON object: {"outer":{"inner":"value"}}
    let mut data: [u8; DATA_BYTES] = [0; DATA_BYTES];
    // {"outer":{"inner":"value"}}
    let json_bytes = [
        123, 34, 111, 117, 116, 101, 114, 34, 58, 123, 34, 105, 110, 110, 101, 114, 34, 58, 34, 118,
        97, 108, 117, 101, 34, 125, 125,
    ];

    for i in 0..json_bytes.len() {
        data[i] = json_bytes[i];
    }
    for i in json_bytes.len()..DATA_BYTES {
        data[i] = 255; // Padding
    }

    let ciphertext_digest = 1;
    let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
    monomials[0] = 1;
    for i in 1..3 * MAX_STACK_HEIGHT {
        monomials[i] = monomials[i - 1] * ciphertext_digest;
    }

    // Create key sequence for "outer.inner" path
    let outer_key_bytes = [111, 117, 116, 101, 114]; // "outer"
    let inner_key_bytes = [105, 110, 110, 101, 114]; // "inner"

    // Use nested object key sequence helper
    let sequence_digest = create_nested_object_key_sequence_with_tree_hasher::<MAX_STACK_HEIGHT, DATA_BYTES>(
        outer_key_bytes,
        inner_key_bytes,
        ciphertext_digest,
        monomials,
    );
    // Value digest for "value"
    let value_bytes = [118, 97, 108, 117, 101]; // "value"
    let value_digest = create_value_digest(value_bytes, ciphertext_digest);

    let state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

    // Calculate data digest
    let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];
    for i in 0..DATA_BYTES {
        let is_padding = if data[i] == 255 { 1 } else { 0 };
        zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
    }
    let step_in_7 = 1;
    let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

    let step_in: [Field; PUBLIC_IO_LENGTH] = [data_digest, 1, 1, 0, 0, 0, 0, step_in_7, 0, 0, 0];

    let extractor = ExtractorState::<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH> {
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
//     let mut data: [u8; DATA_BYTES] = [0; DATA_BYTES];
//     // {"outer":{"inner":"value"}}
//     let json_bytes = [
//         123, 34, 111, 117, 116, 101, 114, 34, 58, 123, 34, 105, 110, 110, 101, 114, 34, 58, 34, 118,
//         97, 108, 117, 101, 34, 125, 125,
//     ];

//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }
//     for i in json_bytes.len()..DATA_BYTES {
//         data[i] = 255; // Padding
//     }

//     // Use a different ciphertext_digest value
//     let ciphertext_digest = 10;

//     let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * MAX_STACK_HEIGHT {
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

//     let state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     // Calculate data digest
//     let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let step_in: [Field; PUBLIC_IO_LENGTH] = [data_digest, 1, 1, 0, 0, 0, 0, step_in_7, 0, 0, 0];

//     let extractor = ExtractorState::<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH> {
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

//     let mut data: [u8; DATA_BYTES] = [255; DATA_BYTES];
//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }

//     let ciphertext_digest = 7;

//     let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     let mut key_value: [Field; DATA_BYTES] = [0; DATA_BYTES];
//     let key = JsonMaskType { is_array_index: true, value: key_value, array_index: 0 };
//     let key_sequence = [key];

//     let (stack, tree_hashes) = json_tree_hasher(ciphertext_digest, key_sequence);

//     let sequence_digest = compress_tree_hash(stack, tree_hashes, monomials);

//     let value_bytes = [52, 50]; // "42"
//     let value_digest = create_value_digest(value_bytes, ciphertext_digest);

//     let state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let sequence_digest_hashed = sequence_digest;

//     let step_in: [Field; PUBLIC_IO_LENGTH] =
//         [data_digest, 0, 0, 0, 0, 0, 0, step_in_7, 0, sequence_digest_hashed, 0];

//     let extractor = ExtractorState::<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH> {
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

//     let mut data: [u8; DATA_BYTES] = [255; DATA_BYTES];
//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }

//     let ciphertext_digest = 7;

//     let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     let mut key1_value: [Field; DATA_BYTES] = [0; DATA_BYTES];
//     key1_value[0] = Field::from(98); // "b"

//     let key1 = JsonMaskType { is_array_index: false, value: key1_value, array_index: 0 };
//     let key2 = JsonMaskType { is_array_index: true, value: [0; DATA_BYTES], array_index: 3 };

//     let key_sequence = [key1, key2];

//     let (stack, tree_hashes) = json_tree_hasher(ciphertext_digest, key_sequence);

//     let sequence_digest = compress_tree_hash(stack, tree_hashes, monomials);

//     let value_bytes = [100]; // "d"
//     let value_digest = create_value_digest(value_bytes, ciphertext_digest);

//     let state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let step_in: [Field; PUBLIC_IO_LENGTH] =
//         [data_digest, 0, 0, 0, 0, 0, 0, step_in_7, 0, sequence_digest, 0];

//     let extractor = ExtractorState::<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH> {
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

//     let mut data: [u8; DATA_BYTES] = [255; DATA_BYTES];
//     for i in 0..json_bytes.len() {
//         data[i] = json_bytes[i];
//     }

//     let ciphertext_digest = 7;

//     let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
//     monomials[0] = 1;
//     for i in 1..3 * MAX_STACK_HEIGHT {
//         monomials[i] = monomials[i - 1] * ciphertext_digest;
//     }

//     let mut key_value: [Field; DATA_BYTES] = [0; DATA_BYTES];
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

//     let state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];

//     let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];
//     for i in 0..DATA_BYTES {
//         let is_padding = if data[i] == 255 { 1 } else { 0 };
//         zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);
//     }
//     let step_in_7 = 1;
//     let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in_7);

//     let sequence_digest_hashed = sequence_digest;

//     let step_in: [Field; PUBLIC_IO_LENGTH] =
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
