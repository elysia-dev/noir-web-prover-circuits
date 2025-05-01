use crate::utils::{is_equal,contains} ;

use super::language::
{
MAX_STACK_HEIGHT ,
START_BRACE, END_BRACE, START_BRACKET, END_BRACKET,
COLON, COMMA,ZERO,ONE,TWO,THREE,FOUR,FIVE,SIX,SEVEN,EIGHT,NINE,N,U,L,F,A,S,E,T,R,PERIOD,E_CHAR,PLUS,MINUS,
QUOTE,ESCAPE
};

// Parser state structure 
// reference : https://github.com/pluto/web-prover-circuits/blob/main/docs/json.md

pub struct ParserState<let N: u32> {
    stack: [[u32; 2]; N],
    tree_hash: [[Field; 2]; N],
    parsing_string: bool,
    parsing_primitive: bool,
    monomial: Field,
    escaped: bool,
}

pub struct StateUpdateHasherInput {
    byte: u8,
    stack: [[u64; 2]; MAX_STACK_HEIGHT],
    parsing_string: bool,
    parsing_primitive: bool,
    polynomial_input: u64,
    monomial: u64,
    tree_hash: [[u64; 2]; MAX_STACK_HEIGHT],
    escaped: bool,
}

// The same strategy applies to outputs 
//  - `next_stack[MAX_STACK_HEIGHT][2]`: the stack machine's stack after reading `byte`.
//  - `next_parsing_string`            : a bool flag that indicates whether the parser is currently parsing a string or not after reading `byte`.
//  - `next_parsing_primitive`            : a bool flag that indicates whether the parser is currently parsing a number or not after reading `byte`.
pub struct StateUpdateHasherOutput {
    next_stack: [[u64; 2]; MAX_STACK_HEIGHT],
    next_parsing_string: bool,
    next_parsing_primitive: bool,
    next_monomial: u64,
    next_tree_hash: [[u64; 2]; MAX_STACK_HEIGHT],
    next_escaped: bool,
}

impl Default for StateUpdateHasherOutput {
    fn default() -> Self {
        StateUpdateHasherOutput {
            next_stack: [[0; 2]; MAX_STACK_HEIGHT],
            next_parsing_string: false,
            next_parsing_primitive: false,
            next_monomial: 0,
            next_tree_hash: [[0; 2]; MAX_STACK_HEIGHT],
            next_escaped: false,
        }
    }
}

//Update current status based on input byte and output the next 
pub fn state_update_hasher(input: StateUpdateHasherInput) -> StateUpdateHasherOutput {
    let byte = input.byte;
    let stack = input.stack;
    let parsing_string = input.parsing_string;
    let parsing_primitive = input.parsing_primitive;
    //let polynomial_input = input.polynomial_input;
    let monomial = input.monomial;
    let tree_hash = input.tree_hash;
    let escaped = input.escaped;
    
    // Break down what was read
    let read_start_brace = is_equal(byte, START_BRACE);
    let read_end_brace = is_equal(byte, END_BRACE);
    let read_start_bracket = is_equal(byte, START_BRACKET);
    let read_end_bracket = is_equal(byte, END_BRACKET);
    let read_colon = is_equal(byte, COLON);
    let read_comma = is_equal(byte, COMMA);
    
    // Read in some delimiter
    let read_delimiter = read_start_brace | read_end_brace | read_start_bracket |
                         read_end_bracket | read_colon | read_comma;
    
    // Read in some primitive
    let primitive_chars:[u8; 23] = [
        ZERO, ONE, TWO, THREE, FOUR, FIVE, SIX, SEVEN, EIGHT, NINE, 
        N, U, L, F, A, S, E, T, R, PERIOD, E_CHAR, PLUS, MINUS
    ];
    
    let read_primitive = contains(byte, primitive_chars);
    
    // // Read in a quote
    let read_quote = is_equal(byte, QUOTE);
    
    // Read in an escape
    let read_escape = is_equal(byte, ESCAPE);
    
    // // Define command instructions (equivalent to Command in Circom)
    let start_brace_instruction = [1, 0, 0];
    let end_brace_instruction = [2, 0, 0];
    let start_bracket_instruction = [3, 0, 0];
    let end_bracket_instruction = [4, 0, 0];
    let colon_instruction = [5, 0, 0];
    let comma_instruction = [6, 0, 0];
    let number_instruction = [0, 0, 1];
    let quote_instruction = [0, 1, 0];
    
    // // Yield instruction based on what byte we read
    let mut instruction = [0,0,0];
    if read_start_brace {
        instruction = start_brace_instruction;
    } else if read_end_brace {
        instruction = end_brace_instruction;
    } else if read_start_bracket {
        instruction = start_bracket_instruction;
    } else if read_end_bracket {
        instruction = end_bracket_instruction;
    } else if read_colon {
        instruction = colon_instruction;
    } else if read_comma {
        instruction = comma_instruction;
    } else if read_primitive {
        instruction = number_instruction;
    } else if read_quote {
        instruction = quote_instruction;
    }
    
    // Get the instruction mask based on current state
    let mask = state_to_mask(read_delimiter, read_primitive, parsing_string, parsing_primitive);
    
    //  Multiply the mask array elementwise with the instruction array
    let mut mul_mask_and_out = [0,0,0];
    for i in 0..3 {
        mul_mask_and_out[i] = mask[i] * instruction[i];
    }
     
    // // Update parsing flags
    let next_parsing_string = if escaped {
        parsing_string
    } else {
        parsing_string ^ (mul_mask_and_out[1] != 0)
    };
    
    let next_parsing_primitive = parsing_primitive | (mul_mask_and_out[2] != 0);

    
    // // Toggle escaped if read
    let next_escaped = read_escape & !escaped;
    
    // Create default output
    let mut output = StateUpdateHasherOutput {
        next_stack: [[0; 2]; MAX_STACK_HEIGHT],
        next_parsing_string: false,
        next_parsing_primitive: false,
        next_monomial: 0,
        next_tree_hash: [[0; 2]; MAX_STACK_HEIGHT],
        next_escaped: false,
    };
    
    // Set output values
    output.next_stack = stack;
    output.next_tree_hash = tree_hash;
    output.next_monomial = monomial;
    output.next_parsing_string = next_parsing_string;
    output.next_parsing_primitive = next_parsing_primitive;
    output.next_escaped = next_escaped;
    
    output
}



// # Inputs:
//  - `readDelimeter` : a bool flag that indicates whether the byte value read was a delimeter.
//  - `readPrimitive`    : a bool flag that indicates whether the byte value read was for a primitive value.
//  - `parsing_string`: a bool flag that indicates whether the parser is currently parsing a string or not.
//  - `parsing_primitive`: a bool flag that indicates whether the parser is currently parsing a number or not.
fn state_to_mask(
    read_delimeter: bool,
    read_primitive: bool,
    parsing_string: bool,
    parsing_primitive: bool
) -> [u64; 3] {
    let mask_rw = !parsing_string as u64;
    let mask_ps = (1 -  parsing_string as u64) as u64;
    
    let parsing_number_read_delim = parsing_primitive as u64 * read_delimeter as u64;
    let read_prim_not_parsing = (!parsing_primitive) as u64 * read_primitive as u64;
    let part1 = (!parsing_string) as u64 * (parsing_number_read_delim + read_prim_not_parsing);
    let part2 = parsing_primitive as u64 * (!read_primitive) as u64 * (!read_delimeter) as u64;
    
    [mask_rw, mask_ps, part1 + part2]
}


pub fn get_top_of_stack(stack: [[u64; 2]; MAX_STACK_HEIGHT]) -> ([u64; 2], u64) {
    let mut value: [u64; 2] = [0, 0]; 
    let mut selector: u64 = 0;
    
    // Count non-zero entries and keep track of values
    for i in 0..MAX_STACK_HEIGHT {
        // Check if stack[i] is not [0,0]
        let is_allocated = stack[i] != [0, 0];
        
        // Increment selector if slot is allocated
        if is_allocated {
            selector += 1;
        }
        
        // Store this value if it's the highest allocated slot
        if is_allocated {
            value = stack[i];
        }
    }
    
    (value, selector)
}


pub struct RewriteStackInput {
    stack: [[u64; 2]; MAX_STACK_HEIGHT],
    tree_hash: [[u64; 2]; MAX_STACK_HEIGHT],
    read_write_value: u64,
    read_start_brace: bool,
    read_start_bracket: bool,
    read_end_brace: bool,
    read_end_bracket: bool,
    read_colon: bool,
    read_comma: bool,
    read_quote: bool,
    escaped: bool,
    parsing_primitive: bool,
    parsing_string: bool,
    next_parsing_string: bool,
    next_parsing_primitive: bool,
    byte: u8,
    polynomial_input: u64,
    monomial: u64,
}

pub struct RewriteStackOutput {
    next_monomial: u64,
    next_stack: [[Field; 2]; MAX_STACK_HEIGHT],
    next_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT],
}


pub fn rewrite_stack(input: RewriteStackInput) -> RewriteStackOutput {
    // Extract all inputs
    let stack = input.stack;
    let tree_hash = input.tree_hash;
    let read_write_value = input.read_write_value;
    let read_start_brace = input.read_start_brace;
    let read_start_bracket = input.read_start_bracket;
    let read_end_brace = input.read_end_brace;
    let read_end_bracket = input.read_end_bracket;
    let read_colon = input.read_colon;
    let read_comma = input.read_comma;
    let read_quote = input.read_quote;
    let escaped = input.escaped;
    let parsing_primitive = input.parsing_primitive;
    let parsing_string = input.parsing_string;
    let next_parsing_string = input.next_parsing_string;
    let next_parsing_primitive = input.next_parsing_primitive;
    let byte = input.byte;
    let polynomial_input = input.polynomial_input;
    let monomial = input.monomial;

    // Composite signals
    let read_colon_and_not_parsing_string = read_colon & !parsing_string;
    let read_comma_and_not_parsing_string = read_comma & !parsing_string;

    // Get top of stack
    let (current_value, pointer) = get_top_of_stack(stack);
    
    // Check if value indicates currently in an array
    let in_array = current_value[0] == 2;
    
    // Composite signals
    let read_comma_in_array = read_comma & in_array;
    let read_comma_not_in_array = read_comma & !in_array;
    
    // Determine whether we are pushing or popping from the stack
    let is_push = (read_start_brace | read_start_bracket) as u64;
    let is_pop = (read_end_brace | read_end_bracket) as u64;
    let next_pointer = pointer as u64 + is_push - is_pop;
    
    // Create indicators for where we are pushing to or popping from
    let mut indicator = [false; MAX_STACK_HEIGHT];
    let mut tree_hash_indicator = [false; MAX_STACK_HEIGHT];
    
    for i in 0..MAX_STACK_HEIGHT {
        indicator[i] = pointer as u64 - is_pop - read_colon_and_not_parsing_string as u64 - read_comma_and_not_parsing_string as u64 == i as u64;
        tree_hash_indicator[i] = pointer as u64 - 1 == i as u64;
    }
    
    // Hash the next_* states to produce hash we need
    let mut state_hash: [[u64; MAX_STACK_HEIGHT + 1]; 2] = [[0; MAX_STACK_HEIGHT + 1]; 2];

    for i in 0..MAX_STACK_HEIGHT {
        state_hash[0][i+1] = state_hash[0][i] + (tree_hash_indicator[i] as u64 * tree_hash[i][0]);
        state_hash[1][i+1] = state_hash[1][i] + (tree_hash_indicator[i] as u64 * tree_hash[i][1]);
    }
    
    let is_object_key = current_value == [1, 0];
    let is_object_value = current_value == [1, 1];
    let is_array = current_value[0] == 2;
    
    let not_to_hash = (parsing_string & next_parsing_string) | next_parsing_primitive;
    let hash_0 = is_object_key as u64 * state_hash[0][MAX_STACK_HEIGHT];
    let hash_1 = ((is_object_value |is_array) as u64) * state_hash[1][MAX_STACK_HEIGHT];
    
    let monomial_is_zero = monomial == 0;
    let increased_power = monomial * polynomial_input;
    let next_monomial = (!not_to_hash as u64) * (monomial_is_zero as u64 + increased_power);
    let option_hash = hash_0 + hash_1 + (byte as u64 * next_monomial);
    
    let mut next_state_hash: [Field; 2] = [0; 2];
    next_state_hash[0] = (not_to_hash as Field * (state_hash[0][MAX_STACK_HEIGHT] - option_hash)as Field) + option_hash as Field;
    next_state_hash[1] = (not_to_hash as Field * (state_hash[1][MAX_STACK_HEIGHT] - option_hash)as Field) + option_hash as Field;
    
   
    // Modify the stack and tree hash
    let stack_change_value = [(is_push + is_pop) * read_write_value, 
                             (read_colon_and_not_parsing_string as u64) + 
                             (read_comma_in_array as u64) - 
                             (read_comma_not_in_array as u64)];
    
    let still_parsing_string = parsing_string & next_parsing_string;
    let still_parsing_object_key = still_parsing_string & is_object_key;
    let end_kv = (!parsing_string) & (read_comma_and_not_parsing_string | read_end_brace | read_end_bracket);
    
    let to_change_zeroth = (!is_array & still_parsing_object_key) | end_kv;
    
    let to_change_first = is_object_value | is_array;
    
    let to_clear_zeroth = end_kv;
    let stopped_parsing_primitive = parsing_primitive & !next_parsing_primitive;
    let read_quote_not_escaped = read_quote & !escaped;
    let not_to_clear_first = !(end_kv | (read_quote_not_escaped & parsing_string) | stopped_parsing_primitive);
    let to_clear_first = !not_to_clear_first;
    
    let tree_hash_change_value = [
        (!to_clear_zeroth as u64) * next_state_hash[0] as u64,
        (!to_clear_first as u64) * next_state_hash[1] as u64
    ];
    
    let mut to_update_hash = [[[false; 2]; MAX_STACK_HEIGHT]; 1];
    for i in 0..MAX_STACK_HEIGHT {
        to_update_hash[0][i][0] = tree_hash_indicator[i] & to_change_zeroth;
        to_update_hash[0][i][1] = tree_hash_indicator[i] & to_change_first;
    }
    
    // Prepare output
    let mut next_stack: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];
    let mut next_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT] = [[0; 2]; MAX_STACK_HEIGHT];

    
    for i in 0..MAX_STACK_HEIGHT {
        next_stack[i][0] = stack[i][0] as Field + (indicator[i] as Field * stack_change_value[0] as Field);
        let second_index_clear = stack[i][1] * ((read_end_brace | read_end_bracket) as u64);
        next_stack[i][1] = stack[i][1] as Field + (indicator[i] as Field * (stack_change_value[1] - second_index_clear) as Field);
        
        if to_update_hash[0][i][0] {
            next_tree_hash[i][0] = tree_hash_change_value[0] as Field ;
        } else {
            next_tree_hash[i][0] = tree_hash[i][0] as Field ;
        }
        
        if to_update_hash[0][i][1] {
            next_tree_hash[i][1] = tree_hash_change_value[1] as Field;
        } else {
            next_tree_hash[i][1] = tree_hash[i][1] as Field;
        }
    }
    
    // Check for underflow or overflow
    // Note: In Noir we don't have `InRange` like in Circom
    // We'd need to ensure pointer is in valid range [0, MAX_STACK_HEIGHT]
    assert(next_pointer >= 0 & next_pointer <= MAX_STACK_HEIGHT as u64, "Stack pointer out of range");
    
    RewriteStackOutput {
        next_monomial,
        next_stack,
        next_tree_hash
    }
}

//This function only for test purpose 
fn create_empty_input(byte: u8) -> StateUpdateHasherInput {
        StateUpdateHasherInput {
            byte,
            stack: [[0; 2]; MAX_STACK_HEIGHT],
            parsing_string: false,
            parsing_primitive: false,
            polynomial_input: 1,
            monomial: 0,
            tree_hash: [[0; 2]; MAX_STACK_HEIGHT],
            escaped: false,
        }
}

#[test]
fn test_state_update_open_brace() {
        let input = create_empty_input(START_BRACE);
        let output = state_update_hasher(input);
        
        assert(output.next_parsing_string == false);
        assert(output.next_parsing_primitive == false);
        assert(output.next_escaped == false);
}

#[test]
    fn test_state_update_string() {
        let input = create_empty_input(QUOTE);
        let output = state_update_hasher(input);
        
        assert(output.next_parsing_string == true);
        assert(output.next_parsing_primitive == false);

        let mut string_input = create_empty_input(ONE);
        string_input.parsing_string = true;
        let string_output = state_update_hasher(string_input);
        
        assert(string_output.next_parsing_string == true);
        assert(string_output.next_parsing_primitive == false);

         let mut end_string_input = create_empty_input(QUOTE);
         end_string_input.parsing_string = true;
         let end_string_output = state_update_hasher(end_string_input);
        
         assert(end_string_output.next_parsing_string == true);
         assert(end_string_output.next_parsing_primitive == false);
    }
#[test]
    fn test_state_update_escape() {
    
        let mut input = create_empty_input(ESCAPE);
        input.parsing_string = true;
        let output = state_update_hasher(input);
        
        assert(output.next_parsing_string == true);
        assert(output.next_escaped == true);
      
        let mut quote_input = create_empty_input(QUOTE);
        quote_input.parsing_string = true;
        quote_input.escaped = true;
        let quote_output = state_update_hasher(quote_input);
        
        assert(quote_output.next_parsing_string == true);
        assert(quote_output.next_escaped == false);
    }

#[test]
    fn test_state_update_number() {
        let input = create_empty_input(ONE);
        let output = state_update_hasher(input);
        
        assert(output.next_parsing_primitive == true);
    
        let mut next_digit_input = create_empty_input(ZERO);
        next_digit_input.parsing_primitive = true;
        let next_digit_output = state_update_hasher(next_digit_input);
        
        assert(next_digit_output.next_parsing_primitive == true);
    }

#[test]
fn test_get_top_of_stack() {
        let empty_stack = [[0; 2]; MAX_STACK_HEIGHT];
        let (value, selector) = get_top_of_stack(empty_stack);
        
        assert(value == [0, 0]);
        assert(selector == 0);
        
        let mut one_item_stack = [[0; 2]; MAX_STACK_HEIGHT];
        one_item_stack[0] = [1, 0];
        let (one_item_value, one_item_selector) = get_top_of_stack(one_item_stack);
        
        assert(one_item_value == [1, 0]);
        assert(one_item_selector == 1);
        
        let mut multi_stack = [[0; 2]; MAX_STACK_HEIGHT];
        multi_stack[0] = [1, 0];
        multi_stack[1] = [2, 1];
        let (multi_value, multi_selector) = get_top_of_stack(multi_stack);
        
        assert(multi_value == [2, 1]);
        assert(multi_selector == 2);
}

#[test]
    fn test_rewrite_stack_object_start() {
        let input = RewriteStackInput {
            stack: [[0; 2]; MAX_STACK_HEIGHT],
            tree_hash: [[0; 2]; MAX_STACK_HEIGHT],
            read_write_value: 1,
            read_start_brace: true,
            read_start_bracket: false,
            read_end_brace: false,
            read_end_bracket: false,
            read_colon: false,
            read_comma: false,
            read_quote: false,
            escaped: false,
            parsing_primitive: false,
            parsing_string: false,
            next_parsing_string: false,
            next_parsing_primitive: false,
            byte: START_BRACE,
            polynomial_input: 1,
            monomial: 0,
        };
        
        let output = rewrite_stack(input);
        
        assert(output.next_stack[0][0] == 1);
        assert(output.next_stack[0][1] == 0);
    }

#[test]
    fn test_rewrite_stack_colon() {
    
        let mut stack = [[0; 2]; MAX_STACK_HEIGHT];
        stack[0] = [1, 0]; 
        
        let input = RewriteStackInput {
            stack,
            tree_hash: [[0; 2]; MAX_STACK_HEIGHT],
            read_write_value: 0,
            read_start_brace: false,
            read_start_bracket: false,
            read_end_brace: false,
            read_end_bracket: false,
            read_colon: true,
            read_comma: false,
            read_quote: false,
            escaped: false,
            parsing_primitive: false,
            parsing_string: false,
            next_parsing_string: false,
            next_parsing_primitive: false,
            byte: COLON,
            polynomial_input: 1,
            monomial: 0,
        };
        
        let output = rewrite_stack(input);

        assert(output.next_stack[0][0] == 1);
        assert(output.next_stack[0][1] == 1);
    }
#[test]
    fn test_simple_json_parsing_workflow() {
    
        let mut stack = [[0; 2]; MAX_STACK_HEIGHT];
        let mut tree_hash = [[0; 2]; MAX_STACK_HEIGHT];
        let mut parsing_string = false;
        let mut parsing_primitive = false;
        let mut monomial = 0;
        let mut escaped = false;
   
        let update_input_1 = StateUpdateHasherInput {
            byte: START_BRACE,
            stack,
            parsing_string,
            parsing_primitive,
            polynomial_input: 1,
            monomial,
            tree_hash,
            escaped,
        };
        
        let update_output_1 = state_update_hasher(update_input_1);
        
        let rewrite_input_1 = RewriteStackInput {
            stack,
            tree_hash,
            read_write_value: 1,
            read_start_brace: true,
            read_start_bracket: false,
            read_end_brace: false,
            read_end_bracket: false,
            read_colon: false,
            read_comma: false,
            read_quote: false,
            escaped,
            parsing_primitive,
            parsing_string,
            next_parsing_string: update_output_1.next_parsing_string,
            next_parsing_primitive: update_output_1.next_parsing_primitive,
            byte: START_BRACE,
            polynomial_input: 1,
            monomial,
        };
        
        let rewrite_output_1 = rewrite_stack(rewrite_input_1);
        
        parsing_string = update_output_1.next_parsing_string;
        parsing_primitive = update_output_1.next_parsing_primitive;
        escaped = update_output_1.next_escaped;
        monomial = rewrite_output_1.next_monomial;
        
        for i in 0..MAX_STACK_HEIGHT {
            stack[i][0] = rewrite_output_1.next_stack[i][0] as u64;
            stack[i][1] = rewrite_output_1.next_stack[i][1] as u64;
            tree_hash[i][0] = rewrite_output_1.next_tree_hash[i][0] as u64;
            tree_hash[i][1] = rewrite_output_1.next_tree_hash[i][1] as u64;
        }
        
        assert(stack[0][0] == 1);
        assert(stack[0][1] == 0);
     
    }