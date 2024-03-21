import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class SHA{

    public static void main(String[] args) {
        try {
            Scanner sc =new Scanner(System.in);
            String secretKey = "Key";
            String message = "Hello";
            byte[] hmac = generateHmacSHA256(secretKey, message.getBytes());

            System.out.println("Original Message: " + message);
            System.out.println("Generated HMAC: " + bytesToHex(hmac));

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }
    }
    private static byte[] generateHmacSHA256(String secretKey, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Key key = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        return mac.doFinal(message);
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}

