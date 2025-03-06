use std::str::Utf8Error;

/// Remove trailing spaces, carriage returns and tabs similar to js an go.
fn must_trim(c: char) -> bool {
    c == ' ' || c == '\t' || c == '\r'
}

fn decode_and_append_line(
    data: &[u8],
    to_append: &mut String,
    trim: bool,
) -> Result<(), Utf8Error> {
    let line_str = std::str::from_utf8(data)?;
    if trim {
        to_append.push_str(line_str.trim_end_matches(must_trim));
    } else {
        to_append.push_str(line_str);
    }
    Ok(())
}

/// Helper function to canonicalized and trim the input data for signature verification.
pub fn to_canonicalized_string(data: &[u8], trim: bool) -> Result<String, Utf8Error> {
    let mut data_sanitized = String::with_capacity(data.len());
    let mut line_idx = 0;
    for (idx, c) in data.iter().enumerate() {
        if *c == b'\n' {
            let line = if idx > 0 && data[idx - 1] == b'\r' {
                &data[line_idx..idx - 1]
            } else {
                &data[line_idx..idx]
            };
            decode_and_append_line(line, &mut data_sanitized, trim)?;
            data_sanitized.push_str("\r\n");
            line_idx = idx + 1;
        }
    }
    if line_idx < data.len() {
        decode_and_append_line(&data[line_idx..data.len()], &mut data_sanitized, trim)?;
    }
    Ok(data_sanitized)
}

pub fn remove_trailing_spaces(data: &str) -> String {
    let mut output = String::with_capacity(data.len());
    let mut lines_iter = data.split('\n');

    if let Some(first) = lines_iter.next() {
        output.push_str(first.trim_end());

        for line in lines_iter {
            output.push('\n');
            output.push_str(line.trim_end());
        }
    }

    output
}

#[cfg(test)]
mod tests {
    use super::{remove_trailing_spaces, to_canonicalized_string};

    fn check_trimmed(input: &str, expected_output: &str) {
        let ouptut = to_canonicalized_string(input.as_bytes(), true).unwrap();
        assert_eq!(ouptut, expected_output);
    }

    fn check(input: &str, expected_output: &str) {
        let ouptut = to_canonicalized_string(input.as_bytes(), false).unwrap();
        assert_eq!(ouptut, expected_output);
    }

    #[test]
    fn test_to_canonicalized_string() {
        check(
            "This is a test\n  \tstring\n    \n\t",
            "This is a test\r\n  \tstring\r\n    \r\n\t",
        );
    }

    #[test]
    fn test_to_canonicalized_string_edge_cases() {
        check("\n", "\r\n");
        check("", "");
        check("\t", "\t");
        check(" ", " ");
    }

    #[test]
    fn test_to_canonicalized_string_edge_canonicalization() {
        check("\r\r\n", "\r\r\n");
        check("\r\r\r\n", "\r\r\r\n");
        check("\r\r\n   hello   ", "\r\r\n   hello   ");
        check("\r\n\n\r\n", "\r\n\r\n\r\n");
        check("\n\n\r\n", "\r\n\r\n\r\n");
    }

    #[test]
    fn test_to_canonicalized_trimmed_string() {
        check_trimmed(
            "This is a test\n  \tstring\n    \n\t",
            "This is a test\r\n  \tstring\r\n\r\n",
        );
    }

    #[test]
    fn test_to_canonicalized_trimmed_string_edge_cases() {
        check_trimmed("\n", "\r\n");
        check_trimmed("", "");
        check_trimmed("\t", "");
        check_trimmed(" ", "");
        check_trimmed("\n \r", "\r\n");
    }

    #[test]
    fn test_to_canonicalized_trimmed_string_edge_canonicalization() {
        check_trimmed("\r\r\n", "\r\n");
        check_trimmed("\r\r\r\n", "\r\n");
        check_trimmed("\r\r\n   hello   ", "\r\n   hello");
        check_trimmed("\r\n\n\r\n", "\r\n\r\n\r\n");
    }

    #[test]
    fn test_remove_trailing_spaces_hello_world() {
        let input = "hello\r\t   \nworld   ";
        let expected = "hello\nworld";
        let observed = remove_trailing_spaces(input);

        assert_eq!(expected, observed);
    }

    #[test]
    fn test_remove_trailing_spaces_empty_string() {
        let input = "";
        let expected = "";
        let observed = remove_trailing_spaces(input);

        assert_eq!(expected, observed);
    }
}
