mod cred;
mod store;

pub use store::Store;

use keyring_core::Error;

pub(crate) fn platform(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::PlatformFailure(Box::new(error))
}
