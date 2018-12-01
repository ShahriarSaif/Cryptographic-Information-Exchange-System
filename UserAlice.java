import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.net.*;
import java.io.*;

public class UserAlice
{
	static final BigInteger alpha = BigInteger.valueOf(3);
	static final BigInteger q = BigInteger.valueOf(353);
	
	public static void main(String args[]) throws Exception
	{
	    Scanner in = new Scanner(System.in);
	    int a = in.nextInt();
	    BigInteger xa = BigInteger.valueOf(a);
		BigInteger ya = alpha.modPow(xa, q);
		
		ServerSocket ss = new ServerSocket(6666);
		Socket soc = ss.accept();
		DataInputStream dis = new DataInputStream(soc.getInputStream());
		DataOutputStream dos = new DataOutputStream(soc.getOutputStream());
		BigInteger yb = BigInteger.valueOf(dis.readInt());
		BigInteger k = yb.modPow(xa, q);
		dos.writeInt(ya.intValue());
		System.out.println(k);
		
	}
}
