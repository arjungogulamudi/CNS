import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.*;
public class DigitalSignature{

    public static void main(String[] args) {
        try {
            // Generate a key pair
            KeyPair keyPair = generateKeyPair();
            Scanner sc=new Scanner(System.in);
            // Get the private and public keys
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            System.out.println("enter the message");
            // Generate a digital signature
            String message = sc.next();
            byte[] signature = sign(message, privateKey);
        //  System.out.println("Signature"+signature);
            System.out.println("Digital Signature: " + Base64.getEncoder().encodeToString(signature));

            // Verify the digital signature
            boolean isVerified = verify(message, signature, publicKey);
            System.out.println("Signature verified: " + isVerified);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Key size
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] sign(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    public static boolean verify(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(message.getBytes());
        return sig.verify(signature);
    }
}