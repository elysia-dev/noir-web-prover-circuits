use http::parse;

/*
pub fn main(data: str<1024>) {
    parse(data);
}
*/

use chacha20::nivc::{NivcState};
use nivc::{FoldingVariables};

global PUBLIC_IO_VARS: u32 = 11;
global DATA_BYTES: u32 = 64;

fn main(
    folding_variables: pub FoldingVariables<PUBLIC_IO_VARS>,
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [u8; DATA_BYTES],
    ciphertext_digest: Field,
    next_pc: Field,
) -> pub FoldingVariables<PUBLIC_IO_VARS> {
    let nivc = NivcState { key, nonce, counter, plaintext, ciphertext_digest };
    let step_out: [Field; PUBLIC_IO_VARS] = nivc.verify(folding_variables.registers);

    FoldingVariables {
        registers: step_out,
        program_counter: next_pc,
    }
}
