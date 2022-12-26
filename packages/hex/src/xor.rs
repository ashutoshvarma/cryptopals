use std::ops::BitXor;

use crate::Hex;

impl BitXor for Hex {
    type Output = Hex;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Hex(self
            .data()
            .iter()
            .zip(rhs.data().iter())
            .map(|(a, b)| a ^ b)
            .collect())
    }
}
