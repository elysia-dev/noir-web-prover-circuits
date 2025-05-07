use chacha20::setup::{SetupState};
use nivc::{FoldingVariables};

global PUBLIC_IO_VARS: u32 = 11;
global DATA_BYTES: u32 = 512;

fn main(
    folding_variables: pub FoldingVariables<PUBLIC_IO_VARS>,
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    plaintext: [Field; DATA_BYTES],
    ciphertext_digest: Field,
    next_pc: Field,
) -> pub FoldingVariables<PUBLIC_IO_VARS> {
    let setup = SetupState { key, nonce, counter, plaintext, ciphertext_digest };
    let step_out: [Field; PUBLIC_IO_VARS] = setup.verify(folding_variables.registers);

    FoldingVariables {
        registers: step_out,
        program_counter: next_pc,
    }
}
