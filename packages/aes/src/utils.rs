pub fn to_arr_range<'a, T, const N: usize>(
    slice: &'a [T],
    range: std::ops::Range<usize>,
) -> Result<&'a [T; N], <&'a [T] as TryInto<&'a [T; N]>>::Error>
where
    &'a [T]: TryInto<&'a [T; N]> + 'a,
    T: Copy,
{
    slice[range].try_into()
}

pub fn to_arr<'a, T, const N: usize>(
    slice: &'a [T],
) -> Result<&'a [T; N], <&'a [T] as TryInto<&'a [T; N]>>::Error>
where
    &'a [T]: TryInto<&'a [T; N]> + 'a,
    // T: Copy,
{
    slice.try_into()
}

// fn word<'a, T>(
//     slice: &'a [T],
//     word_idx: usize,
// ) -> Result<&'a [T; 4], <&'a [T] as TryInto<&'a [T; 4]>>::Error>
// where
//     &'a [T]: TryInto<&'a [T; 4]> + 'a,
//     T: Copy,
// {
//     to_arr_range(slice, (word_idx * 4)..(4 + word_idx * 4))
//     // slice[(word_idx * 4)..(4 + word_idx * 4)].try_into()
// }

pub fn word4<'a, T>(
    slice: &'a [T],
    word_idx: usize,
) -> Result<&'a [T; 16], <&'a [T] as TryInto<&'a [T; 16]>>::Error>
where
    &'a [T]: TryInto<&'a [T; 16]> + 'a,
    T: Copy,
{
    to_arr_range(slice, (word_idx * 4)..(16 + word_idx * 4))
    // slice[(word_idx * 4)..(4 + word_idx * 4)].try_into()
}


