use once_cell::sync::Lazy;
use std::collections::HashMap;

static ENGLISH_SCORES: Lazy<HashMap<char, f64>> = Lazy::new(|| {
    HashMap::from([
        ('E', 12.02),
        ('T', 9.10),
        ('A', 8.12),
        ('O', 7.68),
        ('I', 7.31),
        ('N', 6.95),
        ('S', 6.28),
        ('R', 6.02),
        ('H', 5.92),
        ('D', 4.32),
        ('L', 3.98),
        ('U', 2.88),
        ('C', 2.71),
        ('M', 2.61),
        ('F', 2.30),
        ('Y', 2.11),
        ('W', 2.09),
        ('G', 2.03),
        ('P', 1.82),
        ('B', 1.49),
        ('V', 1.11),
        ('K', 0.69),
        ('X', 0.17),
        ('Q', 0.11),
        ('J', 0.10),
        ('Z', 0.07),
        ('.', 0.0653),
        (',', 0.0613),
        ('"', 0.0267),
        ('\'', 0.0243),
        ('-', 0.0153),
        ('?', 0.0056),
        (':', 0.0034),
        ('!', 0.0033),
        (';', 0.0032),
    ])
});

type CharFrequency = HashMap<char, f64>;

fn get_char_frequency<F: Fn(char) -> bool>(
    value: &str,
    char_filter: F,
) -> (CharFrequency, Vec<char>) {
    let count = value.chars().filter(|&c| char_filter(c)).count();
    value
        .chars()
        .fold((HashMap::new(), Vec::new()), |(mut map, mut max), c| {
            let key = map.entry(c);
            *key.or_insert(0f64) += 1f64 / count as f64;

            if char_filter(c) {
                if max.len() == 0 {
                    max.push(c);
                } else if map.get(&max[0]) < map.get(&c) {
                    max = vec![c];
                } else if map.get(&max[0]) == map.get(&c) && !max.contains(&c) {
                    max.push(c);
                }
            }
            (map, max)
        })
}

impl Metric {
    pub fn score(value: &str) -> Self {
        let (fq, max) = get_char_frequency(&value.to_uppercase(), |_| true);
        let blank_spaces = value.chars().filter(|&c| c == ' ').count();
        let chars_count = value.chars().count();
        let approx_spaces = (chars_count / 5).max(1) - 1;

        let mut naive_score = 0f64;

        for (c, f) in fq.iter() {
            naive_score += (ENGLISH_SCORES.get(c).unwrap_or(&0_f64) * f).sqrt();
        }

        // dbg!((value, blank_spaces, approx_spaces));
        if approx_spaces > blank_spaces {
            naive_score *= 1_f64 - ((approx_spaces - blank_spaces) as f64 / approx_spaces as f64);
        }

        Self {
            char_frequency: fq,
            most_frequent_alphabet: max,
            score: naive_score,
        }
    }
}

#[derive(Debug)]
pub struct Metric {
    pub char_frequency: CharFrequency,
    pub most_frequent_alphabet: Vec<char>,
    pub score: f64,
}

pub trait TextMetric {
    fn text_score(&self) -> f64;
    fn text_metric(&self) -> Metric;
}

impl<T: AsRef<str>> TextMetric for T {
    fn text_score(&self) -> f64 {
        self.text_metric().score
    }
    fn text_metric(&self) -> Metric {
        Metric::score(self.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_scoring() {
        // let value = "Alternatively, to keep it out of the workspace, add the package to the";
        assert_eq!("".text_score(), 0.0);
        assert_eq!(" ".text_score(), 0.0);
    }

    #[test]
    fn test_text_scoring_whitespace_per_word() {
        let value1 = "Alternatively, to keep it out of the workspace, add the package to the";
        let value2 =
            "Alternatively,\0to\0keep\0it\0out\0of\0the\0workspace,\0add\0the\0package\0to\0the";
        // println!("{}, {}", value1.text_score(), value2.text_score());
        debug_assert!(value1.text_score() > value2.text_score());
    }
}
