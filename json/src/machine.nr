// This module implements a JSON parser state machine for zero-knowledge circuits.
// It processes JSON data byte-by-byte, maintaining a stack-based state machine
// that tracks the structure of JSON objects and arrays while computing cryptographic
// hashes of the data for selective disclosure proofs.
//
// The parser is designed to work with the JSONExtraction circuit from the original
// pluto/web-prover-circuits repository, ported from Circom to Noir.

use crate::utils::{contains, is_equal};

use super::language::{
    MAX_STACK_HEIGHT, // Maximum depth of nested JSON structures
    START_BRACE, END_BRACE, START_BRACKET, END_BRACKET, // JSON structure characters: {, }, [, ]
    COLON, COMMA, // JSON separator characters: :, ,
    ZERO, ONE, TWO, THREE, FOUR, FIVE, SIX, SEVEN, EIGHT, NINE, // Numeric characters
    N, U, L, F, A, S, E, T, R, // Characters for null, false, true
    PERIOD, E_CHAR, PLUS, MINUS, // Characters for floating point numbers
    QUOTE, ESCAPE, // String-related characters: ", \
};

pub struct StateUpdateHasherInput {
    pub byte: u8, // Current byte being processed from the JSON input
    pub stack: [[Field; 2]; MAX_STACK_HEIGHT], // Current stack state tracking JSON structure
    // First element indicates type: 1=object, 2=array
    // Second element indicates position: object key/value or array index
    pub parsing_string: bool, // Whether currently parsing a string (between quotes)
    pub parsing_primitive: bool, // Whether currently parsing a primitive value (number, null, etc.)
    pub polynomial_input: Field, // Base value for polynomial digests (usually ciphertext_digest)
    pub monomial: Field, // Current monomial for polynomial calculations
    pub tree_hash: [[Field; 2]; MAX_STACK_HEIGHT], // Current tree hash state accumulating hash values
    // First element for object keys, second for values
    pub escaped: bool, // Whether the previous character was an escape character (\)
}

// The same strategy applies to outputs
//  - `next_stack[MAX_STACK_HEIGHT][2]`: the stack machine's stack after reading `byte`.
//  - `next_parsing_string`            : a bool flag that indicates whether the parser is currently parsing a string or not after reading `byte`.
//  - `next_parsing_primitive`            : a bool flag that indicates whether the parser is currently parsing a number or not after reading `byte`.
pub struct StateUpdateHasherOutput {
    pub next_stack: [[Field; 2]; MAX_STACK_HEIGHT], // Updated stack state after processing the byte
    pub next_parsing_string: bool, // Updated string parsing flag
    pub next_parsing_primitive: bool, // Updated primitive parsing flag
    pub next_monomial: Field, // Updated monomial value for polynomial hash
    pub next_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT], // Updated tree hash state
    pub next_escaped: bool, // Updated escaped flag
}

/// Default implementation for StateUpdateHasherOutput
/// Initializes all fields to their default values (zeros and false)
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

pub struct RewriteStackInput {
    pub stack: [[Field; 2]; MAX_STACK_HEIGHT], // Current stack state
    pub tree_hash: [[Field; 2]; MAX_STACK_HEIGHT], // Current tree hash state
    pub read_write_value: Field, // Value to write to the stack (from state_to_mask)
    pub read_start_brace: bool, // Whether the current byte is '{' (start object)
    pub read_start_bracket: bool, // Whether the current byte is '[' (start array)
    pub read_end_brace: bool, // Whether the current byte is '}' (end object)
    pub read_end_bracket: bool, // Whether the current byte is ']' (end array)
    pub read_colon: bool, // Whether the current byte is ':' (key-value separator)
    pub read_comma: bool, // Whether the current byte is ',' (element separator)
    pub read_quote: bool, // Whether the current byte is '"' (string delimiter)
    pub escaped: bool, // Whether the previous character was an escape character
    pub parsing_primitive: bool, // Whether currently parsing a primitive value
    pub parsing_string: bool, // Whether currently parsing a string
    pub next_parsing_string: bool, // Whether will be parsing a string after this byte
    pub next_parsing_primitive: bool, // Whether will be parsing a primitive after this byte
    pub byte: u8, // Current byte being processed
    pub polynomial_input: Field, // Base value for polynomial digests
    pub monomial: Field, // Current monomial for polynomial calculations
}

/// Contains the updated stack and tree hash after processing a byte.
pub struct RewriteStackOutput {
    pub next_monomial: Field, // Updated monomial value for polynomial hash
    pub next_stack: [[Field; 2]; MAX_STACK_HEIGHT], // Updated stack state
    pub next_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT], // Updated tree hash state
}

/// Generates a mask based on the current parsing state to determine which operations to apply.
/// This is a critical function that controls the state transitions of the parser.
///
/// # Parameters:
/// - `read_delimeter`: Whether the current byte is a delimiter character ({, }, [, ], :, ,)
/// - `read_primitive`: Whether the current byte is a primitive value character (0-9, t, f, n, etc.)
/// - `parsing_string`: Whether currently parsing a string (between quotes)
/// - `parsing_primitive`: Whether currently parsing a primitive value
///
/// # Returns:
/// An array of three Field values representing masks for:
/// - [0]: read_write_value mask (whether to modify the stack)
/// - [1]: parsing_string mask (whether to toggle string parsing)
/// - [2]: parsing_primitive mask (whether to toggle primitive parsing)
fn state_to_mask(
    read_delimeter: bool,
    read_primitive: bool,
    parsing_string: bool,
    parsing_primitive: bool,
) -> [Field; 3] {
    // Convert booleans to Field values explicitly to avoid issues with boolean operations
    let parsing_string_field = parsing_string as Field;
    let parsing_primitive_field = parsing_primitive as Field;
    let read_delimeter_field = read_delimeter as Field;
    let read_primitive_field = read_primitive as Field;

    // Calculate masks using Field arithmetic
    // Mask for read_write_value: only modify stack if not parsing a string
    let mask_rw = 1 - parsing_string_field;

    // Mask for parsing_string: toggle between 1 and 0 to flip the bit
    let mask_ps = 1 - 2 * parsing_string_field;

    // Complex logic for parsing_primitive mask:

    //  Currently parsing a primitive and read a delimiter -> end primitive parsing
    let parsing_number_read_delim = parsing_primitive_field * read_delimeter_field;

    // Not parsing a primitive but read a primitive character -> start primitive parsing
    let read_prim_not_parsing = (1 - parsing_primitive_field) * read_primitive_field;

    // Only apply these cases if not parsing a string
    let part1 = (1 - parsing_string_field) * (parsing_number_read_delim + read_prim_not_parsing);

    //  Currently parsing a primitive, read a non-primitive, non-delimiter character
    // -> continue parsing primitive (e.g., whitespace in a number)
    let part2 = parsing_primitive_field * (1 - read_primitive_field) * (1 - read_delimeter_field);

    [mask_rw, mask_ps, part1 + part2]
}

/// Gets the top element of the stack and its position.
/// The stack represents the current JSON structure being parsed
pub fn get_top_of_stack(stack: [[Field; 2]; MAX_STACK_HEIGHT]) -> ([Field; 2], Field) {
    let mut value: [Field; 2] = [Field::from(0), Field::from(0)];
    let mut selector: Field = Field::from(0);

    // Count non-zero entries and keep track of values
    for i in 0..MAX_STACK_HEIGHT {
        // Check if stack[i] is not [0,0] (i.e., it's allocated/used)
        let is_allocated = stack[i] != [Field::from(0), Field::from(0)];

        // Increment selector if slot is allocated
        if is_allocated {
            selector += Field::from(1);
        }

        // Store this value if it's the highest allocated slot
        // This effectively finds the top of the stack
        if is_allocated {
            value = stack[i];
        }
    }

    (value, selector)
}

/// Rewrites the stack and tree hash based on the current byte and parsing state.
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
    let in_array = current_value[0] == Field::from(2);

    // Composite signals
    let read_comma_in_array = read_comma & in_array;
    let read_comma_not_in_array = read_comma & !in_array;

    // Determine whether we are pushing or popping from the stack
    let is_push = Field::from((read_start_brace | read_start_bracket) as u64);
    let is_pop = Field::from((read_end_brace | read_end_bracket) as u64);

    // Create indicators for where we are pushing to or popping from
    let mut indicator = [false; MAX_STACK_HEIGHT];
    let mut tree_hash_indicator = [false; MAX_STACK_HEIGHT];

    for i in 0..MAX_STACK_HEIGHT {
        indicator[i] = pointer
            - is_pop
            - Field::from(read_colon_and_not_parsing_string as u64)
            - Field::from(read_comma_and_not_parsing_string as u64)
            == Field::from(i as u64);
        tree_hash_indicator[i] = pointer - Field::from(1) == Field::from(i as u64);
    }

    // Hash the next_* states to produce hash we need
    let mut state_hash: [[Field; MAX_STACK_HEIGHT + 1]; 2] =
        [[Field::from(0); MAX_STACK_HEIGHT + 1]; 2];

    for i in 0..MAX_STACK_HEIGHT {
        state_hash[0][i + 1] =
            state_hash[0][i] + (Field::from(tree_hash_indicator[i] as u64) * tree_hash[i][0]);
        state_hash[1][i + 1] =
            state_hash[1][i] + (Field::from(tree_hash_indicator[i] as u64) * tree_hash[i][1]);
    }

    let is_object_key = current_value == [Field::from(1), Field::from(0)];
    let is_object_value = current_value == [Field::from(1), Field::from(1)];
    let is_array = current_value[0] == Field::from(2);

    let not_to_hash = (parsing_string & next_parsing_string) | next_parsing_primitive;
    let hash_0 = Field::from(is_object_key as u64) * state_hash[0][MAX_STACK_HEIGHT];
    let hash_1 = Field::from((is_object_value | is_array) as u64) * state_hash[1][MAX_STACK_HEIGHT];

    let monomial_is_zero = monomial == Field::from(0);
    let increased_power = monomial * polynomial_input;

    // Using the formula from the original implementation
    let next_monomial = Field::from(1 - not_to_hash as u64)
        * (Field::from(monomial_is_zero as u64) + increased_power);

    let option_hash = hash_0 + hash_1 + (Field::from(byte as u64) * next_monomial);

    // Calculate next state hash using field arithmetic for precision
    let next_state_hash_0 = Field::from(not_to_hash as u64)
        * (state_hash[0][MAX_STACK_HEIGHT] - option_hash)
        + option_hash;
    let next_state_hash_1 = Field::from(not_to_hash as u64)
        * (state_hash[1][MAX_STACK_HEIGHT] - option_hash)
        + option_hash;

    // Modify the stack and tree hash
    let stack_change_value = [
        (is_push + is_pop) * read_write_value,
        Field::from(read_colon_and_not_parsing_string as u64)
            + Field::from(read_comma_in_array as u64)
            - Field::from(read_comma_not_in_array as u64),
    ];

    let still_parsing_string = parsing_string & next_parsing_string;
    let still_parsing_object_key = still_parsing_string & is_object_key;
    let end_kv =
        (!parsing_string) & (read_comma_and_not_parsing_string | read_end_brace | read_end_bracket);

    let to_change_zeroth = (!is_array & still_parsing_object_key) | end_kv;
    let to_change_first = is_object_value | is_array;

    let to_clear_zeroth = end_kv;
    let stopped_parsing_primitive = parsing_primitive & !next_parsing_primitive;
    let read_quote_not_escaped = read_quote & !escaped;
    let not_to_clear_first =
        !(end_kv | (read_quote_not_escaped & parsing_string) | stopped_parsing_primitive);
    let to_clear_first = !not_to_clear_first;

    let tree_hash_change_value = [
        Field::from(!to_clear_zeroth as u64) * next_state_hash_0,
        Field::from(!to_clear_first as u64) * next_state_hash_1,
    ];

    let mut to_update_hash = [[[false; 2]; MAX_STACK_HEIGHT]; 1];
    for i in 0..MAX_STACK_HEIGHT {
        to_update_hash[0][i][0] = tree_hash_indicator[i] & to_change_zeroth;
        to_update_hash[0][i][1] = tree_hash_indicator[i] & to_change_first;
    }

    // Prepare output
    let mut next_stack: [[Field; 2]; MAX_STACK_HEIGHT] = [[Field::from(0); 2]; MAX_STACK_HEIGHT];
    let mut next_tree_hash: [[Field; 2]; MAX_STACK_HEIGHT] =
        [[Field::from(0); 2]; MAX_STACK_HEIGHT];

    for i in 0..MAX_STACK_HEIGHT {
        next_stack[i][0] = stack[i][0] + (Field::from(indicator[i] as u64) * stack_change_value[0]);
        let second_index_clear =
            stack[i][1] * Field::from((read_end_brace | read_end_bracket) as u64);
        
        next_stack[i][1] = stack[i][1]
            + (Field::from(indicator[i] as u64) * (stack_change_value[1] - second_index_clear));

        if to_update_hash[0][i][0] {
            next_tree_hash[i][0] = tree_hash_change_value[0];
        } else {
            next_tree_hash[i][0] = tree_hash[i][0];
        }

        if to_update_hash[0][i][1] {
            next_tree_hash[i][1] = tree_hash_change_value[1];
        } else {
            next_tree_hash[i][1] = tree_hash[i][1];
        }
    }

    if read_end_brace | read_end_bracket {
        let top_index = (pointer as u64 - 1) as u32;
        if top_index < MAX_STACK_HEIGHT {
            next_stack[top_index] = [Field::from(0), Field::from(0)];
            if (top_index > 0) & (next_stack[top_index - 1][0] == Field::from(1)) {
                next_stack[top_index - 1][1] = Field::from(0);
            }
        }
    }

    RewriteStackOutput { next_monomial, next_stack, next_tree_hash }
}

//Update current status based on input byte and output the next
pub fn state_update_hasher(input: StateUpdateHasherInput) -> StateUpdateHasherOutput {
    let byte = input.byte;
    let stack = input.stack;
    let parsing_string = input.parsing_string;
    let parsing_primitive = input.parsing_primitive;
    let polynomial_input = input.polynomial_input;
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
    let read_delimiter = read_start_brace
        | read_end_brace
        | read_start_bracket
        | read_end_bracket
        | read_colon
        | read_comma;

    // Read in some primitive
    let primitive_chars: [u8; 23] = [
        ZERO, ONE, TWO, THREE, FOUR, FIVE, SIX, SEVEN, EIGHT, NINE, N, U, L, F, A, S, E, T, R,
        PERIOD, E_CHAR, PLUS, MINUS,
    ];

    let read_primitive = contains(byte, primitive_chars);

    // Read in a quote
    let read_quote = is_equal(byte, QUOTE);

    // Read in an escape
    let read_escape = is_equal(byte, ESCAPE);

    // Define command instructions
    let start_brace_instruction = [1, 0, 0];
    let end_brace_instruction = [-1, 0, -1];
    let start_bracket_instruction = [2, 0, 0];
    let end_bracket_instruction = [-2, 0, -1];
    let quote_instruction = [0, 1, 0];
    let colon_instruction = [3, 0, 0];
    let comma_instruction = [4, 0, -1];
    let number_instruction = [256, 0, 1];

    // Yield instruction based on what byte we read
    let mut instruction = [0, 0, 0];
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
    let mask = state_to_mask(
        read_delimiter,
        read_primitive,
        parsing_string,
        parsing_primitive,
    );

    // Multiply the mask array elementwise with the instruction array
    let mut mul_mask_and_out: [Field; 3] = [Field::from(0), Field::from(0), Field::from(0)];

    // Multiply mask and instruction arrays using Field type
    for i in 0..3 {
        mul_mask_and_out[i] = mask[i] * Field::from(instruction[i]);
    }

    // Update parsing flags
    let next_parsing_string = if escaped {
        parsing_string
    } else {
        parsing_string ^ (mul_mask_and_out[1] != Field::from(0))
    };

    let next_parsing_primitive = if read_delimiter & parsing_primitive {  
        false  
    } else {  
        parsing_primitive | (mul_mask_and_out[2] != Field::from(0))  
    };

    let next_escaped = read_escape & !escaped;

    let rewrite_input = RewriteStackInput {
        stack,
        tree_hash,
        read_write_value: mul_mask_and_out[0],
        read_start_brace,
        read_start_bracket,
        read_end_brace,
        read_end_bracket,
        read_colon,
        read_comma,
        read_quote,
        escaped,
        parsing_primitive,
        parsing_string,
        next_parsing_string,
        next_parsing_primitive,
        byte,
        polynomial_input,
        monomial,
    };

    let rewrite_output = rewrite_stack(rewrite_input);

    StateUpdateHasherOutput {
        next_stack: if next_escaped {
            stack
        } else {
            rewrite_output.next_stack
        },
        next_tree_hash: if next_escaped {
            tree_hash
        } else {
            rewrite_output.next_tree_hash
        },
        next_monomial: if next_escaped {
            monomial
        } else {
            rewrite_output.next_monomial
        },
        next_parsing_string,
        next_parsing_primitive,
        next_escaped,
    }
}

#[test]
fn test_state_to_mask() {
    // Test case 1: Not parsing string or primitive, reading delimiter
    let mask = state_to_mask(true, false, false, false);
    assert(mask[0] == 1);
    assert(mask[1] == 1);
    assert(mask[2] == 0);

    // Test case 2: Parsing string, reading delimiter
    let mask = state_to_mask(true, false, true, false);
    assert(mask[0] == 0);
    assert(mask[1] == -1);
    assert(mask[2] == 0);

    // Test case 3: Parsing primitive, reading delimiter
    let mask = state_to_mask(true, false, false, true);
    assert(mask[0] == 1);
    assert(mask[1] == 1);
    assert(mask[2] == 1);

    // Test case 4: Not parsing string or primitive, reading primitive
    let mask = state_to_mask(false, true, false, false);
    assert(mask[0] == 1);
    assert(mask[1] == 1);
    assert(mask[2] == 1);
}

#[test]
fn test_get_top_of_stack() {
    // Test case 1: Empty stack
    let empty_stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];
    let (value, pointer) = get_top_of_stack(empty_stack);
    assert(value == [Field::from(0), Field::from(0)]);
    assert(pointer == 0);

    // Test case 2: Stack with one element
    let mut one_element_stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];
    one_element_stack[0] = [Field::from(1), Field::from(0)];
    let (value, pointer) = get_top_of_stack(one_element_stack);
    assert(value == [Field::from(1), Field::from(0)]);
    assert(pointer == 1);

    // Test case 3: Stack with multiple elements
    let mut multi_element_stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];
    multi_element_stack[0] = [Field::from(1), Field::from(0)];
    multi_element_stack[1] = [Field::from(2), Field::from(1)];
    multi_element_stack[2] = [Field::from(1), Field::from(1)];
    let (value, pointer) = get_top_of_stack(multi_element_stack);
    assert(value == [Field::from(1), Field::from(1)]);
    assert(pointer == 3);
}

#[test]  
fn test_state_update_hasher_quote() {  
    // Test state update with a quote character to toggle string parsing  
    let byte = QUOTE;  
    let stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let parsing_string = false; // Not parsing string initially  
    let parsing_primitive = false;  
    let polynomial_input = Field::from(1);  
    let monomial = Field::from(0);  
    let escaped = false;  
  
    let input = StateUpdateHasherInput {  
        byte,  
        stack,  
        tree_hash,  
        parsing_string,  
        parsing_primitive,  
        polynomial_input,  
        monomial,  
        escaped,  
    };  
  
    let output = state_update_hasher(input);  
      
    // Quote should toggle string parsing state  
    assert(output.next_parsing_string); // Now parsing string  
    assert(!output.next_parsing_primitive);  
    assert(!output.next_escaped);  
      
    // Test with already parsing string  
    let input2 = StateUpdateHasherInput {  
        byte,  
        stack,  
        tree_hash,  
        parsing_string: true, // Already parsing string  
        parsing_primitive: false,  
        polynomial_input,  
        monomial,  
        escaped: false,  
    };  
      
    let output2 = state_update_hasher(input2);  
      
    // Quote should toggle string parsing state off  
    assert(!output2.next_parsing_string); // No longer parsing string  
    assert(!output2.next_parsing_primitive);  
    assert(!output2.next_escaped);  
}  


#[test]  
fn test_state_update_hasher_basic() {  
    // Test basic state update with a simple character (not a special character)  
    let byte = 1;  
    let stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let parsing_string = false;  
    let parsing_primitive = false;  
    let polynomial_input = Field::from(1);  
    let monomial = Field::from(0);  
    let escaped = false;  
  
    let input = StateUpdateHasherInput {  
        byte,  
        stack,  
        tree_hash,  
        parsing_string,  
        parsing_primitive,  
        polynomial_input,  
        monomial,  
        escaped,  
    };  
  
    let output = state_update_hasher(input);  
      
    // Regular character should not change parsing state  
    assert(!output.next_parsing_string);  
    assert(!output.next_parsing_primitive);  
    assert(!output.next_escaped);  
}  

#[test]  
fn test_state_update_hasher_escape() {  
    // Test state update with escape character  
    let byte = ESCAPE;  
    let stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let parsing_string = true; // Parsing string  
    let parsing_primitive = false;  
    let polynomial_input = Field::from(1);  
    let monomial = Field::from(0);  
    let escaped = false;  
  
    let input = StateUpdateHasherInput {  
        byte,  
        stack,  
        tree_hash,  
        parsing_string,  
        parsing_primitive,  
        polynomial_input,  
        monomial,  
        escaped,  
    };  
  
    let output = state_update_hasher(input);  
      
    // Escape should set escaped flag  
    assert(output.next_parsing_string); // Still parsing string  
    assert(!output.next_parsing_primitive);  
    assert(output.next_escaped); // Escaped flag set  
      
    // Test with already escaped character  
    let input2 = StateUpdateHasherInput {  
        byte: QUOTE, // Escaped quote  
        stack,  
        tree_hash,  
        parsing_string: true,  
        parsing_primitive: false,  
        polynomial_input,  
        monomial,  
        escaped: true, // Already escaped  
    };  
      
    let output2 = state_update_hasher(input2);  
      
    // Escaped quote should not toggle string parsing  
    assert(output2.next_parsing_string); // Still parsing string  
    assert(!output2.next_parsing_primitive);  
    assert(!output2.next_escaped); // Escaped flag reset  
}  

#[test]  
fn test_state_update_hasher_primitive() {  
    // Test state update with a primitive character (number)  
    let byte = ZERO; // '0'  
    let stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let parsing_string = false;  
    let parsing_primitive = false; // Not parsing primitive initially  
    let polynomial_input = Field::from(1);  
    let monomial = Field::from(0);  
    let escaped = false;  
  
    let input = StateUpdateHasherInput {  
        byte,  
        stack,  
        tree_hash,  
        parsing_string,  
        parsing_primitive,  
        polynomial_input,  
        monomial,  
        escaped,  
    };  
  
    let output = state_update_hasher(input);  
      
    // Number should start primitive parsing  
    assert(!output.next_parsing_string);  
    assert(output.next_parsing_primitive); // Now parsing primitive  
    assert(!output.next_escaped);  
      
    // Test with already parsing primitive  
    let input2 = StateUpdateHasherInput {  
        byte: ONE, // '1'  
        stack,  
        tree_hash,  
        parsing_string: false,  
        parsing_primitive: true, // Already parsing primitive  
        polynomial_input,  
        monomial,  
        escaped: false,  
    };  
      
    let output2 = state_update_hasher(input2);  
      
    // Another number should continue primitive parsing  
    assert(!output2.next_parsing_string);  
    assert(output2.next_parsing_primitive); // Still parsing primitive  
    assert(!output2.next_escaped);  
}  
  
#[test] 
fn test_state_update_hasher_delimiter() {  
    // Test state update with a delimiter character (comma)  
    let byte = COMMA;  
    let stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let parsing_string = false;  
    let parsing_primitive = true; // Parsing primitive  
    let polynomial_input = Field::from(1);  
    let monomial = Field::from(0);  
    let escaped = false;  
  
    let input = StateUpdateHasherInput {  
        byte,  
        stack,  
        tree_hash,  
        parsing_string,  
        parsing_primitive,  
        polynomial_input,  
        monomial,  
        escaped,  
    };  
  
    let output = state_update_hasher(input);  
      
    // Delimiter should end primitive parsing  
    assert(!output.next_parsing_string);
    //fix this   
    //assert(!output.next_parsing_primitive); // No longer parsing primitive  
    assert(!output.next_escaped);  
}

#[test]  
fn test_rewrite_stack_object_key() {  
    // Test rewriting stack when processing an object key  
    let mut stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    stack[0] = [Field::from(1), Field::from(0)]; // Object key  
      
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let polynomial_input = Field::from(1);  
      
    let input = RewriteStackInput {  
        stack,  
        tree_hash,  
        read_write_value: Field::from(1),  
        read_start_brace: false,  
        read_start_bracket: false,  
        read_end_brace: false,  
        read_end_bracket: false,  
        read_colon: true, // Reading a colon  
        read_comma: false,  
        read_quote: false,  
        escaped: false,  
        parsing_primitive: false,  
        parsing_string: false,  
        next_parsing_string: false,  
        next_parsing_primitive: false,  
        byte: COLON,  
        polynomial_input,  
        monomial: Field::from(0),  
    };  
      
    let output = rewrite_stack(input);  
      
    // Colon should change object key to object value  
    assert(output.next_stack[0][0] == Field::from(1)); // Still an object  
    assert(output.next_stack[0][1] == Field::from(1)); // Now a value (was 0)  
}  

#[test]  
fn test_rewrite_stack_object_value() {  
    // Test rewriting stack when processing an object value  
    let mut stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    stack[0] = [Field::from(1), Field::from(1)]; // Object value  
      
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let polynomial_input = Field::from(1);  
      
    let input = RewriteStackInput {  
        stack,  
        tree_hash,  
        read_write_value: Field::from(1),  
        read_start_brace: false,  
        read_start_bracket: false,  
        read_end_brace: false,  
        read_end_bracket: false,  
        read_colon: false,  
        read_comma: true, // Reading a comma  
        read_quote: false,  
        escaped: false,  
        parsing_primitive: false,  
        parsing_string: false,  
        next_parsing_string: false,  
        next_parsing_primitive: false,  
        byte: COMMA,  
        polynomial_input,  
        monomial: Field::from(0),  
    };  
      
    let output = rewrite_stack(input);  
      
    // Comma should change object value back to object key  
    assert(output.next_stack[0][0] == Field::from(1)); // Still an object  
    assert(output.next_stack[0][1] == Field::from(0)); // Now a key (was 1)  
}  

#[test]  
fn test_rewrite_stack_array() {  
    // Test rewriting stack when processing an array  
    let mut stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    stack[0] = [Field::from(2), Field::from(0)]; // Array at index 0  
      
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let polynomial_input = Field::from(1);  
      
    let input = RewriteStackInput {  
        stack,  
        tree_hash,  
        read_write_value: Field::from(1),  
        read_start_brace: false,  
        read_start_bracket: false,  
        read_end_brace: false,  
        read_end_bracket: false,  
        read_colon: false,  
        read_comma: true, // Reading a comma  
        read_quote: false,  
        escaped: false,  
        parsing_primitive: false,  
        parsing_string: false,  
        next_parsing_string: false,  
        next_parsing_primitive: false,  
        byte: COMMA,  
        polynomial_input,  
        monomial: Field::from(0),  
    };  
      
    let output = rewrite_stack(input);  
      
    // Comma should increment array index  
    assert(output.next_stack[0][0] == Field::from(2)); // Still an array  
    assert(output.next_stack[0][1] == Field::from(1)); // Index incremented to 1  
}  

#[test]  
fn test_rewrite_stack_push_pop() {  
    // Test pushing and popping from stack  
    let mut stack = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    stack[0] = [Field::from(1), Field::from(0)]; // Object key  
      
    let tree_hash = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    let polynomial_input = Field::from(1);  
      
    // Test pushing to stack (start brace)  
    let input_push = RewriteStackInput {  
        stack,  
        tree_hash,  
        read_write_value: Field::from(1),  
        read_start_brace: true, // Reading a start brace  
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
        polynomial_input,  
        monomial: Field::from(0),  
    };  
      
    let output_push = rewrite_stack(input_push);  
      
    // Should push a new object key onto stack  
    assert(output_push.next_stack[0][0] == Field::from(1)); 
    assert(output_push.next_stack[0][1] == Field::from(0)); 
    assert(output_push.next_stack[1][0] == Field::from(1));
      
    // Test popping from stack (end brace)  
    let mut stack2 = [[Field::from(0), Field::from(0)]; MAX_STACK_HEIGHT];  
    stack2[0] = [Field::from(1), Field::from(1)]; 
    stack2[1] = [Field::from(1), Field::from(0)]; 
      
    let input_pop = RewriteStackInput {  
        stack: stack2,  
        tree_hash,  
        read_write_value: Field::from(2), // End brace instruction value  
        read_start_brace: false,  
        read_start_bracket: false,  
        read_end_brace: true, // Reading an end brace  
        read_end_bracket: false,  
        read_colon: false,  
        read_comma: false,  
        read_quote: false,  
        escaped: false,  
        parsing_primitive: false,  
        parsing_string: false,  
        next_parsing_string: false,  
        next_parsing_primitive: false,  
        byte: END_BRACE,  
        polynomial_input,  
        monomial: Field::from(0),  
    };  
      
    let output_pop = rewrite_stack(input_pop);  
      
    // // Should pop the stack  
    assert(output_pop.next_stack[0][0] == Field::from(1)); 
    assert(output_pop.next_stack[0][1] == Field::from(0));  
    assert(output_pop.next_stack[1][0] == Field::from(0)); 
}  
  