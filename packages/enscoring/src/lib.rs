use std::collections::HashMap;

type CharFrequency = HashMap<char, f64>;

fn get_char_frequency<F: Fn(char) -> bool>(
    value: &str,
    char_filter: F,
) -> (CharFrequency, Vec<char>) {
    let count = value.chars().filter(|&c| char_filter(c)).count();
    let mut res = value
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
        });
    res.0.iter_mut().for_each(|(_, v)| {
        *v *= 100f64;
    });
    res
}

impl Metric {
    pub fn score(value: &str) -> Self {
        let (fq, max) = get_char_frequency(value, |_| true);
        let mut naive_score = 0f64;

        for (c, f) in fq.iter() {
            if c.is_alphabetic() {
                naive_score += f;
            }
        }

        // if there are no whitespaces and not a single word (approx)
        //  then reduce the score by 10%.
        if fq.get(&' ').is_none() && value.len() > 10 {
            naive_score *= 0.9;
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
        let value = "Alternatively, to keep it out of the workspace, add the package to the";
        dbg!(value.text_score());
    }
}
