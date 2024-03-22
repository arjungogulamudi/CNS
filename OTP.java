import java.util.Scanner;

public class OTP {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("Enter plaintext: ");
        String pt = sc.nextLine();
        System.out.print("Enter key: ");
        String key = sc.nextLine();
        if (pt.length() != key.length()) {
            System.out.println("Key length must be equal to plaintext length");
            return;
        }
        StringBuilder ct = new StringBuilder();
        for (int i = 0; i < pt.length(); i++) {
            char ec = (char)(pt.charAt(i) ^ key.charAt(i));
            ct.append(ec);
        }
        System.out.print("Encrypted text (raw): ");
for (int i = 0; i < ct.length(); i++) {
    System.out.print(Integer.toBinaryString((int)ct.charAt(i)) + " ");
}
System.out.println();

        //System.out.println("Encrypted text: " + ct.toString());
        StringBuilder dt = new StringBuilder();
        for (int i = 0; i < ct.length(); i++) {
            char dc = (char) (ct.charAt(i) ^ key.charAt(i));
            dt.append(dc);
        }
        System.out.println("Decrypted text: " + dt.toString());
    }
}