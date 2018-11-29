import static java.lang.Math.pow;

public class DataEncryptStd
{
	private final int p10[] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
	private final int p8[] = {5, 2, 6, 3, 7, 4, 9, 8};
	private final int ip[] = {1, 5, 2, 0, 3, 7, 4, 6};
	private final int ip_inv[] = {3, 0, 2, 4, 6, 1, 7, 5};
	private final int s0[][] = {{1, 0, 3, 2}, {3, 2, 1, 0},
		{0, 2, 3, 1}, {3, 1, 3, 2}};
	private final int s1[][] = {{0, 1, 2, 3}, {2, 0, 1, 3},
		{3, 0, 1, 0}, {2, 1, 0, 3}};
	private final int p4[] = {1, 3, 2, 0};
	private final int BLOCK_SIZE = 8;
	private final int ITER = 2;
	private final int initial_key[];
	private int key[][];
	
	public DataEncryptStd(int initial_key[])
	{
		this.initial_key = initial_key;
		key = new int[2][8];
		generateKey();
	}

	private int[] decToBin(int a, int n)
	{
		int[] bin, invrtd_bin;
		bin = new int[n];
		invrtd_bin = new int[n];
		int i = 0;
		while(a != 0){
			int r = a % 2;
			a /= 2;
			bin[i++] = r;
		}
		if(i != n - 1)
			for(int j = i; j < n; ++j)
				bin[j] = 0;
		for(int j = n - 1; j >= 0; --j)
			invrtd_bin[(n-1)-j] = bin[j];

		return invrtd_bin;
	}

	private int binToDec(int bin[])
	{
		int sum = 0;
		int p = 0;
		for(int i = bin.length - 1; i >= 0; --i)
			sum += bin[i] * pow(2, p++);
		return sum;
	}

	private int[] rotate(int ara[], int n)
	{
		int ara_rotated[] = ara;
		int t;
		while(n-- != 0){
			t = ara_rotated[0];
			int i = 0;
			for(i = 0; i < ara.length - 1; ++i)
				ara_rotated[i] = ara_rotated[i+1];
			ara_rotated[i] = t;
		}
		return ara_rotated;
	}

	private int[] xor(int ara1[], int ara2[])
	{
		int res[] = new int[ara1.length];
		for(int i = 0; i < ara1.length; ++i)
			if(ara1[i] == 0 && ara2[i] == 0)
				res[i] = 0;
			else if((ara1[i] == 0 && ara2[i] == 1) || (ara1[i] == 1 && ara2[i] == 0))
				res[i] = 1;
			else
				res[i] = 0;
		return res;
	}

	private int[] swapBlocks(int ara[])
	{
		int res[] = new int[ara.length];
		for(int i = 0; i < ara.length / 2; ++i)
		    res[ara.length/2+i] = ara[i];
		for(int i = ara.length / 2; i < ara.length; ++i)
		    res[i-4] = ara[i];

		return res;
	}

	private int[] expand(int ara[])
	{
		int res[] = new int[8];
		int j = 3;
		for(int i = 0; i < 8; ++i){
			if(i == 4)
				j = 1;
			res[i] = ara[j];
			j = (j + 1) % 4;
		}
		return res;
	}

	private int[] p10Permutation(int ara[])
	{
		int res[] = new int[10];
		for(int i = 0; i < 10; ++i)
			res[i] = ara[p10[i]];
		return res;
	}

	private int[] p8Permutation(int ara[])
	{
		int res[] = new int[8];
		for(int i = 0; i < 8; ++i)
			res[i] = ara[p8[i]];
		return res;
	}

	private void generateKey()
	{
		int p10_res[] = new int[10];
		int[] right_half, left_half;
		right_half = new int[5];
		left_half = new int[5];
		int temp[] = new int[10];
		p10_res = p10Permutation(initial_key);

		for(int i = 0; i < 2; ++i){
			for(int j = 0; j < 5; ++j)
				left_half[j] = p10_res[j];
			for(int j = 5; j < 10; ++j)
				right_half[j-5] = p10_res[j];
			left_half = rotate(left_half, i+1);
			right_half = rotate(right_half, i+1);
			for(int j = 0; j < 5; ++j)
				temp[j] = left_half[j];
			for(int j = 0; j < 5; ++j)
				temp[5+j] = right_half[j];
			key[i] = p8Permutation(temp);
			p10_res = temp;
		}
	}

	private int[] initPermute(int ara[])
	{
		int res[] = new int[8];
		for(int i = 0; i < 8; ++i)
			res[i] = ara[ip[i]];
		return res;
	}

	private int[] p4Permutation(int ara[])
	{
		int res[] = new int[4];
		for(int i = 0; i < 4; ++i)
			res[i] = ara[p4[i]];
		return res;
	}

	private int[] makeS0(int ara[])
	{
		int res[] = new int[2];
		int row, col;
		int row_ara[] = {ara[0], ara[3]};
		int col_ara[] = {ara[1], ara[2]};
		row = binToDec(row_ara);
		col = binToDec(col_ara);
		int r = s0[row][col];
		res = decToBin(r, 2);
		return res;
	}

	private int[] makeS1(int ara[])
	{
		int res[] = new int[2];
		int row, col;
		int row_ara[] = {ara[0], ara[3]};
		int col_ara[] = {ara[1], ara[2]};
		row = binToDec(row_ara);
		col = binToDec(col_ara);
		int r = s1[row][col];
		res = decToBin(r, 2);
		return res;
	}

	private int[] func(int ara[], int key[])
	{
		int res[] = new int[8];
		int left[] = new int[4];
		int right[] = new int[4];
		for(int i = 0; i < ara.length / 2; ++i) 
		    left[i] = ara[i];
		for(int i = ara.length / 2; i < ara.length; ++i) 
		    right[i-4] = ara[i];

		int left_xor[] = new int[4];
		int right_xor[] = new int[4];
		int expanded[] = expand(right);
		int xor_res[] = xor(expanded, key);
		for(int i = 0; i < 4; ++i)
			left_xor[i] = xor_res[i];
		for(int i = 4; i < 8; ++i)
			right_xor[i-4] = xor_res[i];
		
		int s0_res[] = makeS0(left_xor);
		int s1_res[] = makeS1(right_xor);
		int merged[] = new int[4];
		for(int i = 0; i < 2; ++i)
			merged[i] = s0_res[i];
		for(int i = 0; i < 2; ++i)
			merged[2+i] = s1_res[i];
		
		merged = p4Permutation(merged);
		left = xor(merged, left);
		
		for(int i = 0; i < 4; ++i)
			res[i] = left[i];
		for(int i = 0; i < 4; ++i)
			res[4+i] = right[i];
		return res;
	}

	private int[] invIp(int ara[])
	{
		int res[] = new int[BLOCK_SIZE];
		for(int i = 0; i < BLOCK_SIZE; ++i)
		    res[i] = ara[ip_inv[i]];
		return res;
	} 

	private int[] encrypt(int pt[])
	{
		int ip_res[] = initPermute(pt);
		int i;
		for(i = 0; i < ITER - 1; ++i){
		    ip_res = func(ip_res, key[i]);
		    ip_res = swapBlocks(ip_res);
		}
		ip_res = func(ip_res, key[i]);
		ip_res = invIp(ip_res);
		return ip_res;		
	} 

	private int[] decrypt(int ct[])
	{
		int ip_res[] = initPermute(ct);
		int i;
		
		for(i = ITER - 1; i > 0; --i){
		    ip_res = func(ip_res, key[i]);
		    ip_res = swapBlocks(ip_res);
		}
		ip_res = func(ip_res, key[i]);
		ip_res = invIp(ip_res);
		return ip_res;
	}
	
	public StringBuilder encryptText(StringBuilder pt)
	{
		StringBuilder ct_buffer = new StringBuilder();
		int n = pt.length();
		for(int i = 0; i < n; ++i){
			int b = pt.charAt(i);
			int bin[] = decToBin(b, 8);
			int ret[] = encrypt(bin);
			char c = (char)binToDec(ret);
			ct_buffer.append(c);
		}
		return ct_buffer;
	}
	
	public StringBuilder decryptText(StringBuilder ct)
	{
		StringBuilder pt_buffer = new StringBuilder();
		int n = ct.length();
		for(int i = 0; i < n; ++i){
			int b = ct.charAt(i);
			int bin[] = decToBin(b, 8);
			int ret[] = decrypt(bin);
			char c = (char)binToDec(ret);
			pt_buffer.append(c);
		}
		return pt_buffer;
	}
	
}
