use crate::cred::PortalCredential;
use crate::platform;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use keyring_core::api::CredentialStoreApi;
use keyring_core::{Entry, Error, Result};
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::any::Any;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

fn malformed(error: impl std::fmt::Display) -> Error {
    Error::BadStoreFormat(error.to_string())
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0; N];
    SysRng.try_fill_bytes(&mut bytes).map_err(platform)?;
    Ok(bytes)
}

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

const VERSION: u32 = 1;
fn derive(secret: &[u8], salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0; KEY_LEN]);
    let info = format!("secret-secret-service-keyring-store/{VERSION}/encryption-key");
    Hkdf::<Sha256>::new(Some(salt), secret)
        .expand(info.as_bytes(), key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

fn aad(salt: &[u8; SALT_LEN]) -> [u8; 4 + SALT_LEN] {
    let mut aad = [0; 4 + SALT_LEN];
    aad[..4].copy_from_slice(&VERSION.to_le_bytes());
    aad[4..].copy_from_slice(salt);
    aad
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Record {
    pub(crate) service: String,
    pub(crate) user: String,
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

/// An encrypted credential store unlocked with a caller-provided secret.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Inner>,
}

struct Inner {
    directory: PathBuf,
    path: PathBuf,
    lock_path: PathBuf,
    key: Zeroizing<[u8; KEY_LEN]>,
    salt: [u8; SALT_LEN],
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens or creates `file_name` in `directory` using the supplied secret.
    pub fn new(directory: impl AsRef<Path>, file_name: &str, secret: &[u8]) -> Result<Arc<Self>> {
        std::fs::create_dir_all(directory.as_ref()).map_err(platform)?;

        Self::new_internal(directory, file_name, secret)
    }

    fn new_internal(
        directory: impl AsRef<Path>,
        file_name: &str,
        secret: &[u8],
    ) -> Result<Arc<Self>> {
        let directory = directory.as_ref();
        let file_name = Path::new(file_name);

        let path = directory.join(file_name);
        let lock_path = path_with_suffix(&path, ".lock");

        let _guard = lock(&lock_path)?;

        let existing = read_envelope(&path)?;
        let salt = match &existing {
            Some(envelope) => envelope.salt,
            None => random::<SALT_LEN>()?,
        };

        let store = Self {
            inner: Arc::new(Inner {
                directory: directory.to_path_buf(),
                path,
                lock_path,
                key: derive(secret, &salt),
                salt,
            }),
        };

        match existing {
            Some(envelope) => {
                store.decrypt(&envelope)?;
            }
            None => store.save(&[])?,
        }

        Ok(Arc::new(store))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(self.inner.key.as_ref())
            .expect("32 bytes is a valid XChaCha20Poly1305 key length")
    }

    fn decrypt(&self, envelope: &Envelope) -> Result<Vec<Record>> {
        if envelope.salt != self.inner.salt {
            return Err(malformed("Store salt changed"));
        }

        let plaintext = Zeroizing::new(
            self.cipher()
                .decrypt(
                    &XNonce::from(envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: &aad(&envelope.salt),
                    },
                )
                .map_err(|_| malformed("Wrong secret or corrupted store"))?,
        );

        serde_json::from_slice(&plaintext).map_err(malformed)
    }

    fn encrypt(&self, records: &[Record]) -> Result<Envelope> {
        let nonce = random::<NONCE_LEN>()?;
        let aad = aad(&self.inner.salt);

        let plaintext = Zeroizing::new(serde_json::to_vec(records).map_err(platform)?);
        let ciphertext = self
            .cipher()
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(platform)?;

        Ok(Envelope {
            version: VERSION,
            salt: self.inner.salt,
            nonce,
            ciphertext,
        })
    }

    fn save(&self, records: &[Record]) -> Result<()> {
        let envelope = self.encrypt(records)?;

        let mut file = NamedTempFile::new_in(&self.inner.directory).map_err(platform)?;

        let mut writer = BufWriter::new(file.as_file_mut());
        serde_json::to_writer(&mut writer, &envelope).map_err(platform)?;
        writer.flush().map_err(platform)?;
        writer.get_ref().sync_all().map_err(platform)?;
        drop(writer);

        file.persist(&self.inner.path).map_err(platform)?;

        File::open(&self.inner.directory)
            .and_then(|directory| directory.sync_all())
            .map_err(platform)?;

        Ok(())
    }

    fn load(&self) -> Result<Vec<Record>> {
        let envelope =
            read_envelope(&self.inner.path)?.ok_or_else(|| malformed("Store file disappeared"))?;
        self.decrypt(&envelope)
    }

    pub(crate) fn read<T>(&self, f: impl FnOnce(&[Record]) -> Result<T>) -> Result<T> {
        let _lock = lock(&self.inner.lock_path)?;
        let records = self.load()?;
        f(&records)
    }

    pub(crate) fn update<T>(&self, f: impl FnOnce(&mut Vec<Record>) -> Result<T>) -> Result<T> {
        let _lock = lock(&self.inner.lock_path)?;
        let mut records = self.load()?;
        let result = f(&mut records)?;
        self.save(&records)?;
        Ok(result)
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut new_path = path.as_os_str().to_owned();
    new_path.push(suffix);
    new_path.into()
}

fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(platform)?;
    file.lock().map_err(platform)?;
    Ok(file)
}

fn read_envelope(path: &Path) -> Result<Option<Envelope>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(platform(e)),
    };

    let envelope: Envelope = serde_json::from_slice(&bytes).map_err(malformed)?;
    if envelope.version != VERSION {
        return Err(malformed("Unsupported store version"));
    }
    Ok(Some(envelope))
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        "secret-secret-service-keyring-store".into()
    }

    fn id(&self) -> String {
        format!(
            "{}:{}",
            env!("CARGO_PKG_VERSION"),
            self.inner.path.display()
        )
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        modifiers: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        if modifiers.is_some_and(|m| !m.is_empty()) {
            return Err(Error::Invalid(
                "modifiers".into(),
                "No modifiers are supported".into(),
            ));
        }

        Ok(Entry::new_with_credential(Arc::new(PortalCredential {
            store: self.clone(),
            service: service.into(),
            user: user.into(),
        })))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
