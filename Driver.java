import java.util.Scanner;

public class Driver
{
	public static void main(String args[])
	{
		int key[] = {1, 0, 1, 1, 0, 0, 1, 0, 1, 1};
		String str;
		Scanner in = new Scanner(System.in);
		str = in.nextLine();
		StringBuilder pt = new StringBuilder(str);
		DataEncryptStd des = new DataEncryptStd(key);
		StringBuilder ct = des.encryptText(pt);
		System.out.println("encrypted ciphertext:");
		System.out.println(ct);
		System.out.println("decrypted plaintext:");
		pt = des.decryptText(ct);
		System.out.println(pt);
	}
}