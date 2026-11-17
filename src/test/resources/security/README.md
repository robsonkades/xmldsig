Public, disposable certificates used to test rejection of 512-bit RSA and EC keys.
They are self-signed test material, not trust anchors. No private keys are included.

Generated with JDK 25 `keytool -genkeypair` (`RSA -keysize 512 -sigalg SHA256withRSA`
and `EC -groupname secp256r1 -sigalg SHA256withECDSA`), then exported with
`keytool -exportcert -rfc`. Verification does not rely on certificate dates or trust.
