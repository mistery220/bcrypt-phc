#![doc = include_str!("../README.md")]
#![forbid(missing_docs, rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

extern crate alloc;

use alloc::vec::Vec;
use password_hash::{
    errors::InvalidValue, Encoding, Error, Ident, McfHasher, ParamsString, PasswordHash,
    PasswordHasher, Salt,
};
use zeroize::Zeroizing;

const ALGORITHM: Ident<'static> = Ident::new_unwrap("bcrypt");

/// bcrypt parameters
#[derive(Clone, Copy, Debug)]
pub struct Params {
    cost: u32,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            cost: bcrypt::DEFAULT_COST,
        }
    }
}

impl<'a> TryFrom<&'a PasswordHash<'a>> for Params {
    type Error = Error;

    fn try_from(value: &'a PasswordHash<'a>) -> Result<Self, Self::Error> {
        let rounds = value
            .params
            .get_decimal("r")
            .ok_or(Error::ParamValueInvalid(InvalidValue::Malformed))?;

        Ok(Self { cost: rounds })
    }
}

impl TryInto<ParamsString> for Params {
    type Error = Error;

    fn try_into(self) -> Result<ParamsString, Self::Error> {
        let mut string = ParamsString::new();
        string.add_decimal("r", self.cost)?;
        Ok(string)
    }
}

/// bcrypt hasher
pub struct Bcrypt;

impl PasswordHasher for Bcrypt {
    type Params = Params;

    fn hash_password_customized<'a>(
        &self,
        password: &[u8],
        algorithm: Option<password_hash::Ident<'a>>,
        _version: Option<password_hash::Decimal>,
        params: Self::Params,
        salt: impl Into<password_hash::Salt<'a>>,
    ) -> password_hash::Result<PasswordHash<'a>> {
        if let Some(algorithm) = algorithm {
            if algorithm != ALGORITHM {
                return Err(Error::Algorithm);
            }
        }

        let salt = salt.into();
        let mut salt_bytes = [0; 16];

        // Attempt to decode the salt with the bcrypt alphabet.
        // We are considering this the happy path since the crate is mainly made for gradual migration from bcrypt to something more modern.
        // And we don't re-encode the salts in our conversion function, so they are still bcrypt alphabet encoded.
        if Encoding::Bcrypt
            .decode(salt.as_str(), &mut salt_bytes)
            .is_err()
        {
            salt.decode_b64(&mut salt_bytes)?;
        }

        // Null-terminate the password
        let mut password_vec = Zeroizing::new(Vec::with_capacity(password.len() + 1));
        password_vec.extend_from_slice(password);
        password_vec.push(0);

        // Truncate to match the behaviour of the `bcrypt` crate
        // Not a fan of this behaviour tbh but most implementations do that
        let truncated = if password_vec.len() > 72 {
            &password_vec[..72]
        } else {
            &password_vec
        };

        // Hash the password and remove the last byte
        let raw_hash = bcrypt::bcrypt(params.cost, salt_bytes, truncated);
        let raw_hash = &raw_hash[..23];

        Ok(PasswordHash {
            algorithm: ALGORITHM,
            version: None,
            params: params.try_into()?,
            salt: Some(salt),
            hash: Some(raw_hash.try_into()?),
        })
    }
}

impl McfHasher for Bcrypt {
    fn upgrade_mcf_hash<'a>(&self, hash: &'a str) -> password_hash::Result<PasswordHash<'a>> {
        // Some manual MCF decoding because the bcrypt crate doesn't expose all the necessary fields
        let mut mcf_split = hash.split('$').filter(|part| !part.is_empty()).skip(1);

        let cost = mcf_split
            .next()
            .and_then(|cost_str| cost_str.parse::<u32>().ok())
            .ok_or(Error::ParamValueInvalid(InvalidValue::Malformed))?;

        let mcf_content = mcf_split
            .next()
            .ok_or(Error::ParamValueInvalid(InvalidValue::Malformed))?;

        let b64_salt = &mcf_content[..22];
        let b64_hash = &mcf_content[22..];

        let mut raw_hash = [0; 23];
        Encoding::Bcrypt.decode(b64_hash, &mut raw_hash)?;

        let params = Params { cost }.try_into()?;

        Ok(PasswordHash {
            algorithm: ALGORITHM,
            version: None,
            params,
            salt: Some(Salt::from_b64(b64_salt)?),
            hash: Some(raw_hash.as_ref().try_into()?),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::Bcrypt;
    use password_hash::{McfHasher, PasswordHasher, PasswordVerifier, SaltString};

    #[test]
    fn verify_own() {
        let salt = SaltString::generate(rand::thread_rng());
        let own = Bcrypt.hash_password("test".as_bytes(), &salt).unwrap();
        own.verify_password(&[&Bcrypt], "test").unwrap();
    }

    #[test]
    fn node_phc_test() {
        let hash = "$bcrypt$v=98$r=10$tAe1bhm5zoo0Sx7ZfrCd7w$0T4Cf8htpt/8FbjK+cErdaTh8T6ClYQ";
        let passwd_hash = hash.try_into().unwrap();
        Bcrypt.verify_password(b"password", &passwd_hash).unwrap();
    }

    #[test]
    fn python_mcf_test() {
        let hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
        Bcrypt
            .verify_mcf_hash("correctbatteryhorsestapler".as_bytes(), hash)
            .unwrap();
    }

    #[test]
    fn node_mcf_test() {
        let hash = "$2a$04$n4Uy0eSnMfvnESYL.bLwuuj0U/ETSsoTpRT9GVk5bektyVVa5xnIi";
        Bcrypt
            .verify_mcf_hash("correctbatteryhorsestapler".as_bytes(), hash)
            .unwrap();
    }
}
