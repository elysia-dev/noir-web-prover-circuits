// Delimeters
pub comptime global START_BRACE: u8 = 123; // ASCII `{`
pub comptime global END_BRACE: u8 = 125; // ASCII `}`
pub comptime global START_BRACKET: u8 = 91; // ASCII `[`
pub comptime global END_BRACKET: u8 = 93; // ASCII `]`
pub comptime global QUOTE: u8 = 34; // ASCII `"`
pub comptime global COLON: u8 = 58; // ASCII `:`
pub comptime global COMMA: u8 = 44; // ASCII `,`
pub comptime global ESCAPE: u8 = 92; // ASCII `\`

// Number
pub comptime global ZERO: u8 = 48;
pub comptime global ONE: u8 = 49;
pub comptime global TWO: u8 = 50;
pub comptime global THREE: u8 = 51;
pub comptime global FOUR: u8 = 52;
pub comptime global FIVE: u8 = 53;
pub comptime global SIX: u8 = 54;
pub comptime global SEVEN: u8 = 55;
pub comptime global EIGHT: u8 = 56;
pub comptime global NINE: u8 = 57;

// Null ,True , False ..
pub comptime global N: u8 = 110;
pub comptime global U: u8 = 117;
pub comptime global L: u8 = 108;
pub comptime global F: u8 = 102;
pub comptime global A: u8 = 97;
pub comptime global S: u8 = 115;
pub comptime global E: u8 = 101;
pub comptime global T: u8 = 116;
pub comptime global R: u8 = 114;

// Scientific Notation
// example : 1.23e+4 , or 5.67e-2
pub comptime global PERIOD: u8 = 46; // .
pub comptime global E_CHAR: u8 = 69; // E
pub comptime global PLUS: u8 = 43; // +
pub comptime global MINUS: u8 = 45; // -

//These params are passing into functions in a generic way
//Now they mainly serve for test
pub comptime global TEST_MAX_STACK_HEIGHT: u32 = 12;
pub comptime global TEST_PUBLIC_IO_LENGTH: u32 = 11;
pub comptime global TEST_DATA_BYTES: u32 = 256;
