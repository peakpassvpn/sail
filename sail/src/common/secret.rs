//! A value that must not be shown: a password, a key, a UUID that admits a
//! user. It is read and used as the value it holds, and printed as none, so
//! that the Debug of what holds it can be logged.

/// A secret, read as the value is, printed as `<redacted>`.
#[derive(serde_derive::Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret<T>(pub T);

impl<T> std::fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<T> std::ops::Deref for Secret<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> std::ops::DerefMut for Secret<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_used_but_not_shown() {
        #[derive(serde_derive::Deserialize, Debug)]
        struct Options {
            password: Secret<String>,
            key: Option<Secret<[u8; 2]>>,
        }
        let options: Options =
            serde_json::from_str(r#"{"password": "hunter2", "key": [7, 9]}"#).unwrap();
        assert_eq!(options.password.as_str(), "hunter2");
        assert_eq!(*options.key.unwrap(), [7, 9]);
        let shown = format!("{:?}", options);
        assert!(
            !shown.contains("hunter2") && !shown.contains('7'),
            "{}",
            shown
        );
        assert_eq!(
            shown,
            "Options { password: <redacted>, key: Some(<redacted>) }"
        );
    }
}
