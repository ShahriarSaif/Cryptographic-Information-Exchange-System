import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;
import java.net.*;
import java.io.*;

public class UserBob
{
	static final BigInteger alpha = BigInteger.valueOf(3);
	static final BigInteger q = BigInteger.valueOf(353);

	public static void main(String args[]) throws Exception
	{
	    Scanner in = new Scanner(System.in);
	    int b = in.nextInt();
	    BigInteger xb = BigInteger.valueOf(b);
		BigInteger yb = alpha.modPow(xb, q);
		Socket soc = new Socket("localhost", 6666);
		DataInputStream dis = new DataInputStream(soc.getInputStream());
		DataOutputStream dos = new DataOutputStream(soc.getOutputStream());
		dos.writeInt(yb.intValue());
		BigInteger ya = BigInteger.valueOf(dis.readInt());
		BigInteger k = ya.modPow(xb, q);
		System.out.println(k);

	}
}
