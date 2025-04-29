
use crate::utils::hash_utils::{is_equal, is_zero, contains};
use crate::language::{
    MAX_STACK_HEIGHT,
    START_BRACE, END_BRACE, START_BRACKET, END_BRACKET,
    COLON, COMMA, ZERO, ONE, TWO, THREE, FOUR, FIVE, SIX, SEVEN, EIGHT, NINE, 
    N, U, L, F, A, S, E, T, R, PERIOD, E_CHAR, PLUS, MINUS, QUOTE, ESCAPE
};
use crate::parser::{
    ParserState,
    StateUpdateHasherInput, StateUpdateHasherOutput,
    state_update_hasher, get_top_of_stack, 
    RewriteStackInput, RewriteStackOutput, rewrite_stack
};

mod tests {
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

        let mut string_input = create_empty_input(b'a');
        string_input.parsing_string = true;
        let string_output = state_update_hasher(string_input);
        
        assert(string_output.next_parsing_string == true);
        assert(string_output.next_parsing_primitive == false);

        let mut end_string_input = create_empty_input(QUOTE);
        end_string_input.parsing_string = true;
        let end_string_output = state_update_hasher(end_string_input);
        
        assert(end_string_output.next_parsing_string == false);
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
}


