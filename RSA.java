import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;

    // Constructor to generate the public and private keys
    public RSA(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bitLength / 2, 100, random);
        BigInteger q = new BigInteger(bitLength / 2, 100, random);
        modulus = p.multiply(q);

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        publicKey = new BigInteger("65537"); // Common value for public key
        while (phi.gcd(publicKey).intValue() > 1) {
            publicKey = publicKey.add(new BigInteger("2"));
        }

        privateKey = publicKey.modInverse(phi);
    }

    // Encryption method
    public BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, modulus);
    }

    // Decryption method
    public BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(privateKey, modulus);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA(1024); // Initialize RSA with 1024-bit key length

        // Message to be encrypted
        String message = "Hello, RSA!";
        BigInteger plaintext = new BigInteger(message.getBytes());

        // Encrypt the message
        BigInteger ciphertext = rsa.encrypt(plaintext);
        System.out.println("Ciphertext: " + ciphertext);

        // Decrypt the message
        BigInteger decryptedMessage = rsa.decrypt(ciphertext);
        System.out.println("Decrypted message: " + new String(decryptedMessage.toByteArray()));
    }
}