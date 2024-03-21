import java.util.Scanner;
public class Cipher{
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the input text: ");
        String plainText = scanner.nextLine();
        System.out.print("Enter the secret key: ");
        int key = scanner.nextInt();
        String caesarCipherText = caesarCipher(plainText, key);
        System.out.println("Cipher text is: " + caesarCipherText);
        System.out.println("Decrypted text for each key:");
        for (int i = 1; i <= 26; i++) {
            String decryptedText = caesarDecipher(caesarCipherText, i);
            System.out.println("At key " + i + ": " + decryptedText);
        }
        System.out.println("Match found at"+key+":"+plainText);
        scanner.close();
    }
    private static String caesarCipher(String text, int key) {
        StringBuilder result = new StringBuilder();
        for (char ch : text.toCharArray()) {
            if (Character.isLetter(ch)) {
                char base = Character.isLowerCase(ch) ? 'a' : 'A';
                result.append((char) (((ch - base + key) % 26) + base));
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }
    private static String caesarDecipher(String text, int key) {
        return caesarCipher(text, 26 - key);
    }
}