// pub static SBOX_TABLE: [u8; 256] = calculate_aes_sbox();

#[inline(always)]
const fn rotl8(x: u8, shift: u8) -> u8 {
    ((x) << (shift)) | ((x) >> (8 - (shift)))
}

pub const fn calculate_aes_sbox() -> [u8; 256] {
    let mut table: [u8; 256] = [0_u8; 256];

    let mut p = 1u8;
    let mut q = 1u8;

    /* loop invariant: p * q == 1 in the Galois field */
    loop {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (if (p & 0x80) != 0x0 { 0x1B } else { 0 });

        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= if (q & 0x80) != 0x0 { 0x09 } else { 0 };

        /* compute the affine transformation */
        let xformed = q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4);

        table[p as usize] = xformed ^ 0x63;

        if p == 1 {
            break;
        }
    }

    /* 0 is a special case since it has no inverse */
    table[0] = 0x63;

    table
}
