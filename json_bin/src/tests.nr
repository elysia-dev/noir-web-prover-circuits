use crate::{main, FoldingVariables, PUBLIC_IO_VARS};

#[test]
fn test_main() {
    let key: [u32; 8] = [0; 8];
    let nonce: [u32; 3] = [0; 3];
    let counter: u32 = 0;
    let plaintext: [u8; DATA_BYTES] = [0; DATA_BYTES];
    let ciphertext_digest: Field = 0;
    let next_pc: Field = 0;

    let result: FoldingVariables<PUBLIC_IO_VARS> = main(
        FoldingVariables {
            registers: [0; PUBLIC_IO_VARS],
            program_counter: 0,
        },
        key,
        nonce,
        counter,
        plaintext,
        ciphertext_digest,
        next_pc,
    );

    assert_eq!(result.registers, [0; PUBLIC_IO_VARS]);
}
