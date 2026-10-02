//! The inbounds as a host or the management API sees them, and their
//! users by name: a user's credentials added to an inbound, replaced, or
//! taken out of it, each read, changed and written back under the lock
//! changes take, so that two at once do not undo one another.
//!
//! None of it is kept: the configuration file is what a restart or a
//! reload goes by.

use crate::{Error, RuntimeManager};

/// An inbound as it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InboundInfo {
    pub tag: String,
    /// Its type, as the configuration has it: `trojan`, `tun`.
    pub protocol: String,
    pub listen: Option<String>,
    pub listen_port: Option<u16>,
    /// Whether its users and certificate change while it runs, without
    /// its socket rebound.
    pub reloadable: bool,
}

/// Why a change to an inbound's users was not made.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InboundError {
    #[error("[{0}] inbound: does not exist")]
    NoInbound(String),
    #[error("[{0}] inbound: its users and certificate change only with a reload or a restart")]
    NotReloadable(String),
    #[error("[{0}] inbound: user [{1}] is in it already")]
    UserExists(String, String),
    #[error("[{0}] inbound: user [{1}] is not in it")]
    NoUser(String, String),
    /// The credentials do not do, as the configuration would refuse them.
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Failed(#[from] Error),
}

/// The name a credential, an entry of an inbound's `users`, gives.
fn name_of(user: &serde_json::Value) -> Option<&str> {
    ["name", "username"]
        .iter()
        .find_map(|field| user.get(*field).and_then(|v| v.as_str()))
}

impl RuntimeManager {
    /// The inbounds, by tag.
    pub fn inbounds(&self) -> Result<Vec<InboundInfo>, Error> {
        let inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        Ok(inbounds
            .configs()
            .into_iter()
            .map(|i| InboundInfo {
                reloadable: inbounds.reloadable(&i.tag),
                tag: i.tag,
                protocol: i.protocol,
                listen: i.listen,
                listen_port: i.listen_port,
            })
            .collect())
    }

    /// The names of the users of the inbound `tag`, sorted; none when there
    /// is no such inbound. Their credentials are not told.
    pub fn inbound_users(&self, tag: &str) -> Result<Option<Vec<String>>, Error> {
        let inbounds = self
            .inbound_manager
            .lock()
            .map_err(|_| Error::RuntimeManager)?;
        Ok(inbounds.config(tag).map(|config| {
            let mut names: Vec<String> =
                config.user_names().into_iter().map(str::to_owned).collect();
            names.sort();
            names
        }))
    }

    /// Changes the `users` of the inbound `tag` by `change`, under the
    /// lock changes take, and puts them in force; what `change` returns.
    async fn change_users<T>(
        &self,
        tag: &str,
        change: impl FnOnce(&mut Vec<serde_json::Value>) -> Result<T, InboundError>,
    ) -> Result<T, InboundError> {
        let _update = self.update.lock().await;
        let mut inbound = {
            let inbounds = self
                .inbound_manager
                .lock()
                .map_err(|_| Error::RuntimeManager)?;
            let inbound = inbounds
                .config(tag)
                .ok_or_else(|| InboundError::NoInbound(tag.to_string()))?;
            if !inbounds.reloadable(tag) {
                return Err(InboundError::NotReloadable(tag.to_string()));
            }
            inbound
        };
        let users = inbound
            .options
            .entry("users")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| {
                InboundError::Invalid(format!("[{}] inbound: users is not a list", tag))
            })?;
        let changed = change(users)?;
        self.update_inbound_resources_locked(&inbound)
            .map_err(|e| match e {
                Error::Config(e) => InboundError::Invalid(format!("{:#}", e)),
                e => InboundError::Failed(e),
            })?;
        Ok(changed)
    }

    /// Adds `user`, an entry of the inbound's `users` as its protocol has
    /// them, with a name of its own, to the inbound `tag`.
    pub async fn add_inbound_user(
        &self,
        tag: &str,
        user: serde_json::Value,
    ) -> Result<(), InboundError> {
        let Some(name) = name_of(&user).map(str::to_owned) else {
            return Err(InboundError::Invalid(format!(
                "[{}] inbound: a user added needs a name",
                tag
            )));
        };
        self.change_users(tag, |users| {
            if users.iter().any(|u| name_of(u) == Some(&name)) {
                return Err(InboundError::UserExists(tag.to_string(), name));
            }
            users.push(user);
            Ok(())
        })
        .await
    }

    /// Replaces the credentials of the user `name` in the inbound `tag` by
    /// `user`, which names it too, or no one: as a password is changed.
    /// Its connections go on, as sing-box's do: what it opened with the
    /// old credential stays open until it is disconnected.
    pub async fn replace_inbound_user(
        &self,
        tag: &str,
        name: &str,
        mut user: serde_json::Value,
    ) -> Result<(), InboundError> {
        match name_of(&user) {
            Some(given) if given != name => {
                return Err(InboundError::Invalid(format!(
                    "[{}] inbound: the user is named [{}], not [{}]",
                    tag, given, name
                )))
            }
            Some(_) => {}
            None => {
                let Some(fields) = user.as_object_mut() else {
                    return Err(InboundError::Invalid(format!(
                        "[{}] inbound: a user is an object",
                        tag
                    )));
                };
                // The field the inbound's other users are named by.
                fields.insert("name".into(), name.into());
            }
        }
        self.change_users(tag, |users| {
            let before = users.len();
            users.retain(|u| name_of(u) != Some(name));
            if users.len() == before {
                return Err(InboundError::NoUser(tag.to_string(), name.to_string()));
            }
            users.push(user);
            Ok(())
        })
        .await
    }

    /// Takes the user `name` out of the inbound `tag`: its credentials
    /// there go, and so do its connections through it.
    pub async fn remove_inbound_user(&self, tag: &str, name: &str) -> Result<(), InboundError> {
        self.change_users(tag, |users| {
            let before = users.len();
            users.retain(|u| name_of(u) != Some(name));
            if users.len() == before {
                return Err(InboundError::NoUser(tag.to_string(), name.to_string()));
            }
            Ok(())
        })
        .await
    }
}
