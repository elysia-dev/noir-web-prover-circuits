use crate::machine::{state_update_hasher, StateUpdateHasherInput, RewriteStackInput, rewrite_stack};  
use crate::language::{  
    DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_LENGTH,  
    START_BRACE, END_BRACE, START_BRACKET, END_BRACKET,  
    COLON, COMMA, QUOTE  
};  
use crate::utils::{polynomial_digest, polynomial_digest_with_counter, is_equal, create_nested_object_key_sequence,create_value_digest};  


// It processes JSON data byte-by-byte to find and extract specific values  
/// - `data`: The JSON data bytes to process  
/// - `ciphertext_digest`: Base value for polynomial digests  
/// - `sequence_digest`: Digest of the key sequence (path) to the target value  
/// - `value_digest`: Digest of the expected value to extract  
/// - `state`: Initial parser state  
/// - `step_in`: Input step variables from previous circuit  
pub fn extract(    
    data: [u8; DATA_BYTES],    
    ciphertext_digest: Field,    
    sequence_digest: Field,    
    value_digest: Field,    
    state: [Field; MAX_STACK_HEIGHT * 4 + 4],    
    step_in: [Field; PUBLIC_IO_LENGTH]    
) -> [Field; PUBLIC_IO_LENGTH] {    
    // Verify input state digest matches expected value     
    let input_state_digest = polynomial_digest(state, ciphertext_digest);    
    assert(step_in[8] == input_state_digest);    
    
    // Initialize monomials for polynomial digests      
    // These are used to calculate state digests efficiently   
    let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];    
    monomials[0] = 1;    
    for i in 1..3 * MAX_STACK_HEIGHT {    
        monomials[i] = monomials[i - 1] * ciphertext_digest;    
    }    
    
    // Initialize state tracking variables    
    let mut state_digest: [Field; DATA_BYTES] = [0; DATA_BYTES];    
    let mut sequence_is_matched: [Field; DATA_BYTES] = [0; DATA_BYTES];    
    let mut value_is_matched: [Field; DATA_BYTES] = [0; DATA_BYTES];    
    let mut total_matches = 0;    
    
    // Initialize parser state from input state    
    let mut prev_stack: [[Field; 2]; MAX_STACK_HEIGHT] = [[Field::from(0); 2]; MAX_STACK_HEIGHT];    
    let mut prev_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT] = [[Field::from(0); 2]; MAX_STACK_HEIGHT];    
    let mut prev_monomial = state[MAX_STACK_HEIGHT * 4];    
    let mut prev_parsing_string = state[MAX_STACK_HEIGHT * 4 + 1] != 0;    
    let mut prev_parsing_primitive = state[MAX_STACK_HEIGHT * 4 + 2] != 0;    
    let mut prev_escaped = state[MAX_STACK_HEIGHT * 4 + 3] != 0;    
    
    for i in 0..MAX_STACK_HEIGHT {    
        prev_stack[i] = [state[i * 2], state[i * 2 + 1]];    
        prev_tree_hash[i] = [state[MAX_STACK_HEIGHT * 2 + i * 2], state[MAX_STACK_HEIGHT * 2 + i * 2 + 1]];    
    }    
    
    // Process each byte of input data    
    for data_idx in 0..DATA_BYTES {    
        // Create state update input    
        let update_input = StateUpdateHasherInput {    
            byte: data[data_idx],    
            stack: prev_stack,    
            tree_hash: prev_tree_hash,    
            parsing_string: prev_parsing_string,    
            parsing_primitive: prev_parsing_primitive,    
            polynomial_input: ciphertext_digest,    
            monomial: prev_monomial,    
            escaped: prev_escaped,    
        };    
    
        // Update state based on current byte    
        let update_output = state_update_hasher(update_input);    
            
        // Create rewrite stack input    
        let rewrite_input = RewriteStackInput {    
            stack: update_output.next_stack,    
            tree_hash: update_output.next_tree_hash,    
            read_write_value: Field::from(1),    
            read_start_brace: is_equal(data[data_idx], START_BRACE),    
            read_start_bracket: is_equal(data[data_idx], START_BRACKET),    
            read_end_brace: is_equal(data[data_idx], END_BRACE),    
            read_end_bracket: is_equal(data[data_idx], END_BRACKET),    
            read_colon: is_equal(data[data_idx], COLON),    
            read_comma: is_equal(data[data_idx], COMMA),    
            read_quote: is_equal(data[data_idx], QUOTE),    
            escaped: update_input.escaped,    
            parsing_primitive: update_input.parsing_primitive,    
            parsing_string: update_input.parsing_string,    
            next_parsing_string: update_output.next_parsing_string,    
            next_parsing_primitive: update_output.next_parsing_primitive,    
            byte: data[data_idx],    
            polynomial_input: ciphertext_digest,    
            monomial: update_input.monomial,    
        };    
            
        // Rewrite stack based on current state    
        let rewrite_output = rewrite_stack(rewrite_input);    
            
        // Update state for next iteration    
        prev_stack = rewrite_output.next_stack;    
        prev_tree_hash = rewrite_output.next_tree_hash;    
        prev_monomial = rewrite_output.next_monomial;    
        prev_parsing_string = update_output.next_parsing_string;    
        prev_parsing_primitive = update_output.next_parsing_primitive;    
        prev_escaped = update_output.next_escaped;    
    
        // Calculate state digest    
        let mut accumulator = Field::from(0);    
        for i in 0..MAX_STACK_HEIGHT {    
            accumulator += prev_stack[i][0] * monomials[3 * i];    
            accumulator += prev_stack[i][1] * monomials[3 * i + 1];    
            accumulator += prev_tree_hash[i][0] * monomials[3 * i + 2];    
        }    
        state_digest[data_idx] = accumulator;    
    
        // Check if sequence matches    
        sequence_is_matched[data_idx] = if state_digest[data_idx] == sequence_digest { 1 } else { 0 };    
        
        // Check if value matches    
        let mut value_digest_in_stack = Field::from(0);    
        for i in 0..MAX_STACK_HEIGHT {    
            value_digest_in_stack += prev_tree_hash[i][1];    
        }    
        value_is_matched[data_idx] = if value_digest == value_digest_in_stack { 1 } else { 0 };    
    
        // Update total matches    
        let matched = sequence_is_matched[data_idx] * value_is_matched[data_idx];    
        total_matches += matched;  
            
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
        all_padding = all_padding & (data[i] == 255);  
    }  
  
    // If all bytes are padding, set digest to 0, otherwise calculate normally    
    let new_state_digest = if all_padding {      
        0      
    } else {      
        polynomial_digest(new_state, ciphertext_digest)      
    };  
  
    // Calculate ciphertext digest powers and handle padding    
    let mut ciphertext_digest_pow: [Field; DATA_BYTES + 1] = [0; DATA_BYTES + 1];    
    ciphertext_digest_pow[0] = step_in[7];    
    let mut zeroed_data: [Field; DATA_BYTES] = [0; DATA_BYTES];    
    for i in 0..DATA_BYTES {    
        let is_padding = if data[i] == 255 { 1 } else { 0 };    
        zeroed_data[i] = (1 - is_padding) * Field::from(data[i]);    
        let mult_factor = (1 - is_padding) * ciphertext_digest + is_padding;    
        ciphertext_digest_pow[i + 1] = ciphertext_digest_pow[i] * mult_factor;    
    }    
    let data_digest = polynomial_digest_with_counter(zeroed_data, ciphertext_digest, step_in[7]);    
    
    // Prepare output    
    let mut step_out: [Field; PUBLIC_IO_LENGTH] = [0; PUBLIC_IO_LENGTH];    
    step_out[0] = step_in[0] - data_digest + value_digest * total_matches;    
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
    let is_value_digest_zero = (value_digest == 0) as u8;    
    let is_new_state_digest_zero = (new_state_digest == 0) as u8;    
    let is_step_out_zero_matched = (step_out[0] == value_digest) as u8;    
    
    assert((1 - is_value_digest_zero) * (is_new_state_digest_zero - is_step_out_zero_matched) == 0);    
      
    println(step_out[0]);    
    println(value_digest);    
    println(total_matches);    
    println(sequence_digest);    
    println(data_digest);  
      
    step_out    
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
  
    let step_out = extract(data, ciphertext_digest, sequence_digest, value_digest, state, step_in);  
  
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
        123, 34, 111, 117, 116, 101, 114, 34, 58, 123, 34, 105, 110, 110, 101, 114,   
        34, 58, 34, 118, 97, 108, 117, 101, 34, 125, 125  
    ];   
      
    for i in 0..json_bytes.len() {  
        data[i] = json_bytes[i];  
    }  
    for i in json_bytes.len()..DATA_BYTES {  
        data[i] = 255; // Padding  
    }  
  
    let ciphertext_digest = 1;  
      
    // Create key sequence for "outer.inner" path  
    let outer_key_bytes = [111, 117, 116, 101, 114]; // "outer"  
    let inner_key_bytes = [105, 110, 110, 101, 114]; // "inner"  
      
    // Use nested object key sequence helper  
    let sequence_digest = create_nested_object_key_sequence(outer_key_bytes, inner_key_bytes, ciphertext_digest);  
      
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
  
    let step_out = extract(data, ciphertext_digest, sequence_digest, value_digest, state, step_in);  
  
    // Verify output  
    assert(step_out[0] == value_digest);  
    assert(step_out[7] == ciphertext_digest.pow_32(json_bytes.len() as Field));  
}  
  
