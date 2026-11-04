use crate::store::{Record, Store};

use keyring_core::api::CredentialApi;
use keyring_core::{Credential, Error};
use std::any::Any;
use std::sync::Arc;
use zeroize::Zeroizing;

pub(crate) struct PortalCredential {
    pub(crate) store: Store,
    pub(crate) service: String,
    pub(crate) user: String,
}

impl std::fmt::Debug for PortalCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortalCredential")
            .field("service", &self.service)
            .field("user", &self.user)
            .finish_non_exhaustive()
    }
}

impl PortalCredential {
    fn position(&self, records: &[Record]) -> Result<usize, Error> {
        records
            .iter()
            .position(|r| r.service == self.service && r.user == self.user)
            .ok_or(Error::NoEntry)
    }
}

impl CredentialApi for PortalCredential {
    fn set_secret(&self, secret: &[u8]) -> Result<(), Error> {
        self.store.update(|records| {
            match self.position(records) {
                Ok(i) => {
                    records[i].secret = Zeroizing::new(secret.to_vec());
                }
                Err(_) => records.push(Record {
                    service: self.service.clone(),
                    user: self.user.clone(),
                    secret: Zeroizing::new(secret.to_vec()),
                }),
            }
            Ok(())
        })
    }

    fn get_secret(&self) -> Result<Vec<u8>, Error> {
        self.store
            .read(|records| Ok(records[self.position(records)?].secret.to_vec()))
    }

    fn delete_credential(&self) -> Result<(), Error> {
        self.store.update(|records| {
            records.remove(self.position(records)?);
            Ok(())
        })
    }

    fn get_credential(&self) -> Result<Option<Arc<Credential>>, Error> {
        self.store.read(|records| {
            self.position(records)?;
            Ok(None)
        })
    }

    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
