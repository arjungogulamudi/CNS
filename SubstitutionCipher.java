import java.util.*;
public class SubstitutionCipher{
public static String  xoring(String a, String b){
    String ans = "";
        for (int i = 0; i < a.length(); i++)
        {
            if (a.charAt(i) == b.charAt(i))
                ans += "0";
            else
                ans += "1";
        }
        return ans;
    }

public static void main(String[] args){
    Scanner sc=new Scanner(System.in);
    System.out.println("enter the Plaintext");
    String s=sc.nextLine();
    System.out.println("enter the Key");
    String k=sc.nextLine();
    if(s.length()!=k.length()){
        int ind=s.length()-k.length();
        int ki=k.length();
        for(int i=0;i<ind;i++){
            if(s.length()!=k.length()){
            k=k+k.charAt(i%ki);
        }
        else{
        break;
        }
        }//for
    }//if
    String ciphertext="";
    for(int i=0;i<s.length();i++){
    String a=Integer.toBinaryString(s.charAt(i));
    String b=Integer.toBinaryString(k.charAt(i));
    String c=xoring(a,b);
    ciphertext+=c+" ";
    }
    System.out.println("ciphertext :"+ciphertext);
    String[] words=ciphertext.split("\\s");
    String plain="";
    for(int i=0;i<words.length;i++){
    String a=Integer.toBinaryString(k.charAt(i));
    String c=xoring(a,words[i]);
    int asciiValue = Integer.parseInt(c, 2);
    char character = (char) asciiValue;
    plain+=character;
    }
    System.out.println("Plaintext:"+plain);
    }
}