from ipv8.keyvault.crypto import default_eccrypto

# Generate a curve25519 key pair
private_key = default_eccrypto.generate_key("curve25519")

# Save the private key to a .pem file
with open("my_key.pem", "wb") as f:
    f.write(private_key.key_to_bin())

print("Public key (hex):", private_key.pub().key_to_bin().hex())
print("Key saved to my_key.pem")