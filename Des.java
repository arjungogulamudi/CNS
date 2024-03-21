import java.util.*;
import javax.crypto.*;
class Des {
    public static void main(String args[]) throws Exception{
        boolean flag=true;
        while(flag){
        Scanner sc=new Scanner(System.in);
        SecretKey sk= KeyGenerator.getInstance("DES").generateKey();
        System.out.println("enter plaintext");
        String planetext=sc.nextLine();
        Cipher ec,de;
        byte[] enc;
        ec=Cipher.getInstance("DES");
        de=Cipher.getInstance("DES");
        ec.init(Cipher.ENCRYPT_MODE,sk);
        byte[] utf8 = planetext.getBytes("UTF8");
        enc = ec.doFinal(utf8);
        System.out.println("encripted text  "+Base64.getEncoder().encodeToString(enc));
        String eText=Base64.getEncoder().encodeToString(enc);
        de.init(Cipher.DECRYPT_MODE,sk);
        byte[] dec = Base64.getDecoder().decode(eText);
        byte[] utf82 = de.doFinal(dec);
        System.out.println("Decripted Text  "+ new String(utf82, "UTF8"));
        System.out.println("To countinue press 'y'");
        String a=sc.nextLine();
        if(a.equalsIgnoreCase("y")){
            flag=true;
        }
        else{
            flag=false;
        }
        }
    }
}