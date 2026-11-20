use rand_core::{OsRng, RngCore};
use sers_core::SersError;

/// `N` random bytes from the operating system CSPRNG.
pub fn random_array<const N: usize>() -> Result<[u8; N], SersError> {
    let mut out = [0u8; N];
    OsRng
        .try_fill_bytes(&mut out)
        .map_err(|_| SersError::Crypto("operating system RNG failure"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consecutive_draws_differ() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
