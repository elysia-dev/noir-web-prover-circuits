use json::extractor::ExtractorState;
use nivc::FoldingVariables;

global PUBLIC_IO_VARS: u32 = 11;
global DATA_BYTES: u32 = 512;
global MAX_STACK_HEIGHT: u32 = 12;

fn main(
    folding_variables: pub FoldingVariables<PUBLIC_IO_VARS>,
    data: [u8; DATA_BYTES],
    ciphertext_digest: Field,
    sequence_digest: Field,
    value_digest: Field,
    state: [Field; MAX_STACK_HEIGHT * 4 + 4],
    next_pc: Field,
) -> pub FoldingVariables<PUBLIC_IO_VARS> {
    let extractor = ExtractorState::<DATA_BYTES, MAX_STACK_HEIGHT, PUBLIC_IO_VARS> {
        data,
        ciphertext_digest,
        sequence_digest,
        value_digest,
        state,
    };

    let step_out: [Field; PUBLIC_IO_VARS] = extractor.extract(folding_variables.registers);

    FoldingVariables { registers: step_out, program_counter: next_pc }
}
