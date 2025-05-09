use crate::machine::{state_update_hasher, StateUpdateHasherInput};
use crate::utils::{compress_tree_hash, polynomial_digest, polynomial_digest_with_counter};

pub struct ExtractorState<let DATA_BYTES: u32, let MAX_STACK_HEIGHT: u32, let PUBLIC_IO_LENGTH: u32> {
    pub data: [u8; DATA_BYTES],
    pub ciphertext_digest: Field,
    pub sequence_digest: Field,
    pub value_digest: Field,
    pub state: [Field; MAX_STACK_HEIGHT * 4 + 4],
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

            let mut tmp_state_digest = state_digest[data_idx] ;
            println(f"sequence_matched: {tmp_state_digest}"); //0x044f
            let mut sequence_digest =self.sequence_digest;
            println(f"sequence_digest: {sequence_digest}");// 0x0463

            //let mut tmp_sequence_matched = sequence_is_matched[data_idx];
            //println(f"sequence_digest: {self.sequence_digest}");
            //println(f"sequence_matched: {tmp_sequence_matched}");

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

        let mut temp = step_out[0];
        let mut temp_value_digest = self.value_digest;
        let mut temp_sequence_digest = self.sequence_digest;

        println(f"step_out[0]: {temp}");
        println(f"value_digest: {temp_value_digest}");
        println(f"total_matches: {total_matches}");
        println(f"sequence_digest: {temp_sequence_digest}");
        println(f"data_digest: {data_digest}");

        println(f"is_value_digest_zero: {is_value_digest_zero}");
        println(f"is_new_state_digest_zero: {is_new_state_digest_zero}");
        println(f"is_step_out_zero_matched: {is_step_out_zero_matched}");

        assert(
            (1 - is_value_digest_zero) * (is_new_state_digest_zero - is_step_out_zero_matched) == 0,
        );
      
        step_out
    }
}
