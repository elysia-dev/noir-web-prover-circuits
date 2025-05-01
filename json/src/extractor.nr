use crate::machine::{state_update_hasher,StateUpdateHasherInput};
use crate::language::{DATA_BYTES,MAX_STACK_HEIGHT,PUBLIC_IO_LENGTH};
use crate::utils::{polynomial_digest,polynomial_digest_with_counter};

pub fn extract(
    data: [u8; DATA_BYTES],               
    ciphertext_digest: Field,                 
    sequence_digest: Field,                  
    value_digest: Field,                      
    state: [Field; MAX_STACK_HEIGHT * 4 + 4], 
    step_in: [Field; PUBLIC_IO_LENGTH]        
) -> pub [Field; PUBLIC_IO_LENGTH] {          

    let input_state_digest = polynomial_digest(state, ciphertext_digest);
    assert(step_in[8] == input_state_digest);

    let mut monomials: [Field; 3 * MAX_STACK_HEIGHT] = [0; 3 * MAX_STACK_HEIGHT];
    monomials[0] = 1;
    for i in 1..3 * MAX_STACK_HEIGHT {
        monomials[i] = monomials[i - 1] * ciphertext_digest;
    }

    let mut state_digest: [Field; DATA_BYTES] = [0; DATA_BYTES];
    let mut sequence_is_matched: [Field; DATA_BYTES] = [0; DATA_BYTES];
    let mut value_is_matched: [Field; DATA_BYTES] = [0; DATA_BYTES];
    let mut total_matches = 0;

    let mut prev_stack: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];
    let mut prev_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];
    let mut prev_monomial = state[MAX_STACK_HEIGHT * 4];
    let mut prev_parsing_string = state[MAX_STACK_HEIGHT * 4 + 1] != 0;
    let mut prev_parsing_primitive = state[MAX_STACK_HEIGHT * 4 + 2] != 0;
    let mut prev_escaped = state[MAX_STACK_HEIGHT * 4 + 3] != 0;

    for i in 0..MAX_STACK_HEIGHT {
        prev_stack[i] = [state[i * 2], state[i * 2 + 1]];
        prev_tree_hash[i] = [state[MAX_STACK_HEIGHT * 2 + i * 2], state[MAX_STACK_HEIGHT * 2 + i * 2 + 1]];
    }

    for data_idx in 0..DATA_BYTES {
       
        let input = StateUpdateHasherInput {
            byte: data[data_idx],
            stack: prev_stack.map(|x| [x[0] as u64, x[1] as u64]),
            tree_hash: prev_tree_hash.map(|x| [x[0] as u64, x[1] as u64]),
            parsing_string: prev_parsing_string,
            parsing_primitive: prev_parsing_primitive,
            polynomial_input: ciphertext_digest as u64,
            monomial: prev_monomial as u64,
            escaped: prev_escaped,
        };

        let output = state_update_hasher(input);

        prev_stack = output.next_stack.map(|x| [x[0] as Field, x[1] as Field]);
        prev_tree_hash = output.next_tree_hash.map(|x| [x[0] as Field, x[1] as Field]);
        prev_monomial = output.next_monomial as Field;
        prev_parsing_string = output.next_parsing_string;
        prev_parsing_primitive = output.next_parsing_primitive;
        prev_escaped = output.next_escaped;

        let mut accumulator = 0;
        for i in 0..MAX_STACK_HEIGHT {
            accumulator += prev_stack[i][0] * monomials[3 * i];
            accumulator += prev_stack[i][1] * monomials[3 * i + 1];
            accumulator += prev_tree_hash[i][0] * monomials[3 * i + 2];
        }
        state_digest[data_idx] = accumulator;

        sequence_is_matched[data_idx] = if state_digest[data_idx] == sequence_digest { 1 } else { 0 };

        let mut value_digest_in_stack = 0;
        for i in 0..MAX_STACK_HEIGHT {
            value_digest_in_stack += prev_tree_hash[i][1];
        }
        value_is_matched[data_idx] = if value_digest == value_digest_in_stack { 1 } else { 0 };

      
        let matched = sequence_is_matched[data_idx] * value_is_matched[data_idx];
        total_matches += matched;
    }

  
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
    let new_state_digest = polynomial_digest(new_state, ciphertext_digest);

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

    assert(step_out[1] == step_out[2]);
    let is_value_digest_zero = if value_digest == 0 { 1 } else { 0 };
    let is_new_state_digest_zero = if new_state_digest == 0 { 1 } else { 0 };
    let is_step_out_zero_matched = if step_out[0] == value_digest { 1 } else { 0 };
    assert((1 - is_value_digest_zero) * (is_new_state_digest_zero - is_step_out_zero_matched) == 0);

    step_out
}
//////////////////////////////////////////////////////////////////////////////////////////////////////

#[test]  
fn test_http_response_extraction() {
    //Initialize ciphertext
    //e.g."HTTP/1.1 200 OK\r\ncontent-type: a"
    let ciphertext: [u8; DATA_BYTES] = [
        72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13,
        10, 99, 111, 110, 116, 101, 110, 116, 45, 116, 121, 112, 101, 58, 32, 97
    ]; 

    //Compute ciphertext digest 
    let mut ciphertext_fields: [Field; DATA_BYTES] = [0; DATA_BYTES];
    for i in 0..DATA_BYTES {
        ciphertext_fields[i] = ciphertext[i] as Field;
    }
    let ciphertext_digest = polynomial_digest_with_counter(
        ciphertext_fields,
        0,
        1
    );

    //Initialize initial_state 
    let mut initial_state: [Field; MAX_STACK_HEIGHT * 4 + 4] = [0; MAX_STACK_HEIGHT * 4 + 4];
    initial_state[0] = 1;
    initial_state[MAX_STACK_HEIGHT * 4] = 1; 

    //Initialize step_in
    let mut step_in: [Field; PUBLIC_IO_LENGTH] = [0; PUBLIC_IO_LENGTH];
    step_in[7] = 1; // pow_ctr
    step_in[8] = polynomial_digest(initial_state, ciphertext_digest); 

    //Mock values
    let sequence_digest = 12345; 
    let value_digest = 67890;    

    let step_out = extract(
        ciphertext,
        ciphertext_digest,
        sequence_digest,
        value_digest,
        initial_state,
        step_in
    );

    assert(step_out[8] != 0);
  
    //Verify data_digest and total_matches
    let mut ciphertext_fields_masked: [Field; DATA_BYTES] = [0; DATA_BYTES];
    for i in 0..DATA_BYTES {
        ciphertext_fields_masked[i] = if ciphertext[i] == 255 { 0 } else { ciphertext[i] as Field };
    }
    let expected_data_digest = polynomial_digest_with_counter(
        ciphertext_fields_masked,
        ciphertext_digest,
        step_in[7]
    );
    println(expected_data_digest);
    
    let mut pow_chain = 1;
    for i in 0..DATA_BYTES {
        if ciphertext[i] != 255 {
            pow_chain = pow_chain * ciphertext_digest;
        }
    }
    assert(step_out[7] == pow_chain);

}


