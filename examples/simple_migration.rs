use argon2::Argon2;
use bcrypt_phc::Bcrypt;
use password_hash::{McfHasher, PasswordHash};

fn main() {
    // You have an old MCF string because you, for example, migrated from an old Rails application
    // So you take the hash and re-encode it into the PHC format
    let mcf_hash = "$2b$04$EGdrhbKUv8Oc9vGiXX0HQOxSg445d458Muh7DAHskb6QbtCvdxcie";
    let new_phc_string = Bcrypt.upgrade_mcf_hash(mcf_hash).unwrap().to_string();

    println!("Old MCF string: {mcf_hash}");
    println!("New PHC string: {new_phc_string}");

    // And now you can save the PHC string into the database with the other PHC strings (for example, Argon2 hashes)
    // Here comes the `password_hash` crate into play. You can decode the hash and then verify against a bunch of hashes.
    let decoded_hash: PasswordHash<'_> = new_phc_string.as_str().try_into().unwrap();
    decoded_hash
        .verify_password(
            &[&Argon2::default(), &Bcrypt],
            b"correctbatteryhorsestapler",
        )
        .unwrap();

    println!("Verification successful!");

    // This construct then attempts to first verify it against Argon2 and then against BCrypt
    // Note that this in most cases won't run the actual algorithm for each element, but instead just check the algorithm tag
    //
    // Then, when the user decides to change their password, we just hash it with Argon2 instead.
    // And with this your gradual migration is complete.
}
