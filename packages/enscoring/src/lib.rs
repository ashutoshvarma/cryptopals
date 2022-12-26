use std::collections::HashMap;

type CharFrequency = HashMap<char, usize>;

fn get_char_frequency(value: &str) -> (CharFrequency, Option<char>) {
    value
        .chars()
        .fold((HashMap::new(), None), |(mut map, mut max), c| {
            let key = map.entry(c);
            *key.or_insert(0) += 1;

            if let Some(m) = max {
                if map.get(&m) < map.get(&c) && c.is_ascii_alphabetic() {
                    max = Some(c);
                }
            } else if c.is_ascii_alphabetic() {
                max = Some(c)
            }
            (map, max)
        })
}

impl TextMetric {
    pub fn score(value: &str) -> Self {
        let (fq, max) = get_char_frequency(value);
        Self {
            char_frequency: fq,
            most_frequent_alphabet: max,
        }
    }
}

#[derive(Debug)]
pub struct TextMetric {
    pub char_frequency: CharFrequency,
    pub most_frequent_alphabet: Option<char>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_text_scoring() {
        let value = "Alternatively, to keep it out of the workspace, add the package to the";
        let metric = TextMetric::score(value);
        dbg!(metric);
    }
}
