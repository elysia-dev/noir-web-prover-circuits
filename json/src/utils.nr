

pub mod hash_utils {


    pub fn is_equal(a: u8, b: u8) -> bool {
        a == b
    }

    pub fn is_zero(a: u8) -> bool {
        if a == 0 {true} else { false }
    }

    pub fn contains<let N: u32>(value: u8, array: [u8; N]) -> bool {
        let mut result = 0;
        for i in 0..N {
            if is_equal(value, array[i]) {
                result += 1;
            }
        }
        result as bool
    }


   

}
