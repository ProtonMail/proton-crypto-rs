use base64::{prelude::BASE64_STANDARD as BASE_64, Engine as _};

const TEST_MODULUS: &str = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";

fn test_mailbox_password_hash_helper(password: &str, salt: &str, expected_hash: &str) {
    let raw_salt = BASE_64.decode(salt).unwrap();
    let hash = proton_srp::mailbox_password_hash(password, &raw_salt).unwrap();
    assert_eq!(hash.as_bytes(), expected_hash.as_bytes());
}

fn test_srp_password_hash_helper(password: &str, salt: &str, expected_hash: &str) {
    let raw_salt = BASE_64.decode(salt).unwrap();
    let raw_modulus = BASE_64.decode(TEST_MODULUS).unwrap();
    let expected = BASE_64.decode(expected_hash).unwrap();
    let hash = proton_srp::srp_password_hash(4, password, &raw_salt, &raw_modulus).unwrap();
    assert_eq!(hash.as_ref(), expected);
}

#[test]
fn test_mailbox_password_hash() {
    test_mailbox_password_hash_helper(
        "password",
        "imK9IHsRcA2Zsv+yROZgbw==",
        "$2y$10$gkI7GFqPa.0Xqt8wPMXeZuQ.Gd9rSsqE0xQ8Qcf0Q9ckInb4hIzOu",
    );
    test_mailbox_password_hash_helper(
        "a loooong password~~~?\n\n",
        "6hGAnuIZ7Dgf3f/diExc6A==",
        "$2y$10$4fE.lsGX5Bed1d9bgCva4.5x5DgJBFXMNlS93R3YxYVVxR7Jq8V3q",
    );
    test_mailbox_password_hash_helper(
        "t",
        "rNBLbNt14Nuo9lzr6/QpVg==",
        "$2y$10$pL/JZLrz2Lsm7jxp49OnTeQSN9nb4NyO/HCMNYgPTztxZHDF9XRVO",
    );
}

#[test]
fn test_srp_password_hash() {
    test_srp_password_hash_helper(
        "password", 
        "nlPyLLmzfxbmpg==", 
        "1DaNzc9NfToyuSmOBiFVRAofhDKKvA82jqqDJV152Qme+7DArz/gQLdTPGGOHIGqeIl1YY2Leo69J4ED6a+qGwuuxgugfsjs3ACC3YNDocU9/b2/nnCDwHbp0ygNbKe/2sL5e1NE5WApxzsQNqBLmLccrOJ9ci6FUcTWvaSwTkC/wdNWaQEIMx5FIo9b1lnkU5sJPYyOqVoz6cYAGjrAkIzRaJ9u6vD58H7DntIpLRCdg0PBEcYcRwSO6x/oqJhqZw+OibqmX/bLngAJ/gm4O3arAqPy9L4OHdNR3hdhrNOj5iWKRIy/m4UYYMTO/wPzD2EqaZZP8tvOSpR9DBPwFQ=="
    );
    test_srp_password_hash_helper(
        "complex password~~????;&&++", 
        "deDPBSWDYz990Q==", 
        "uzT+PZQD99hBTXdJC6pUgLlRWsOOMSc152mKk9V/TcTYVawoI4sMDxOiFsWusys7l0E/r/i3k8lX2TNYFJ5o3sQfAzMXbnPNeyS1VxzY5nzmkmeu9YgEdH8vwGoxsMy/XD4zyfwP7hQGjOWH4UUYrqgg6sMv4EgnwImCI6XUyJ9Z28JHU4TCUbLF8TIolsVXX2xFBb0blguqf3w2ETbxkKpr2GZQvJD5VXhsptaO7FC/MbA5cvV+2gP8PZGThYXob0wmjCBasEnv5da3ZlUL2h7aX7UDilxQVP6jN4+xTPjKg5tymsdiXZl5/pAr9tHKDiH6mZCJ+CbfXA7wxDSk0Q=="
    );
    test_srp_password_hash_helper(
        "t", 
        "2PAWF2sAwezq0w==", 
        "ickwfLUx8qW2yrt7KUAkRFD/DMKDlZatiDtSc31VaDE07gsImWJs9i7XOGXAKh10FLgYijj+kH3mVZGXpGWDKnfDEWvXtR0K73gdKhPSdVAZ3e4wMqGbjkUhePFdjNEg65NixWYbc4lmLoGYjAkm2hPAlD9X4zvLS7qCmHlJsJcF2qsbwZ+TFz5BIFJr51Kb5vPyJ1j4YmyDW0hSiRe2ZwE1qCwsERIKaebkugecpp4wnceJfvjNDe2e8sKILRUJjhgYtK8nI/XplaMTWdtIE/z0YM6b9rfb3X0r91czidbhE3cCeNw6WLU2dCN0/MRRRs62i9ko3bB14Bp6cCzykw=="
    );
}
