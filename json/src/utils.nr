

    use crate::language::{DATA_BYTES,MAX_STACK_HEIGHT} ;

    pub fn is_equal(a: u8, b: u8) -> bool {
        a == b
    }

    pub fn is_zero(a: u8) -> bool {
        a == 0
    }

    pub fn contains<let N: u32>(value: u8,array: [u8; N]) -> bool {
        array.any(|x| x == value)
    }

    pub fn polynomial_digest(bytes: [Field; DATA_BYTES], polynomial_input: Field) -> Field {
        let mut digest = 0;
        let mut monomial = 1;
        for i in 0..DATA_BYTES {
            digest += bytes[i] * monomial;
            monomial *= polynomial_input;
        }
        digest
    }

    pub fn polynomial_digest_with_counter(bytes: [Field; DATA_BYTES], polynomial_input: Field, pow_ctr: Field) -> Field {
            let mut digest = 0;
            let mut monomial = pow_ctr;
            for i in 0..DATA_BYTES {
                digest += bytes[i] * monomial;
                monomial *= polynomial_input;
            }
            digest
    }

    pub struct JsonMaskType {
        pub is_array_index: bool, 
        pub value: [Field; 32],
        pub array_index: u32,
    }

    
    pub fn json_tree_hasher<let N: u32>(ct_digest: Field, key_sequence: [JsonMaskType; N], max_stack_height: u32) 
     -> ([[Field; 2]; MAX_STACK_HEIGHT], [[Field; 2]; MAX_STACK_HEIGHT]) {
        
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


  


