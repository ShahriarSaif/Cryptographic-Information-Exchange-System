import static java.lang.Math.pow;

public class DataEncryptStd
{
	private int p10[] = {2, 4, 1, 6, 3, 9, 0, 8, 7, 5};
	private int p8[] = {5, 2, 6, 3, 7, 4, 9, 8};
	private int ip[] = {1, 5, 2, 0, 3, 7, 4, 6};
	private int ip_inv[] = {3, 0, 2, 4, 6, 17, 5};
	private int s0[][] = {{1, 0, 3, 2}, {3, 2, 1, 0},
						  {0, 2, 1, 3}, {3, 1, 3, 2}};
	private int s1[][] = {{0, 1, 2, 3}, {2, 0, 1, 3},
						  {3, 0, 1, 0}, {2, 1, 0, 3}};
	private int p4[] = {2, 4, 3, 1};

	private final int BLOCK_SIZE = 8;
	private final int KEY_SIZE = 10;
	private int ciphertext, plaintext;

	public int[] decToBin(int a, int n)
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

	public int binToDec(int bin[])
	{
		int sum = 0;
		int p = 0;
		for(int i = 7; i >= 0; --i)
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
			if(ara1[i] == 1 || ara2[i] == 1)
				res[i] = 1;
			else if(ara1[i] == 0 && ara2[i] == 0)
				res[i] = 0;
			else
				res[i] = 0;
		return res;
	}

	private int[] swapBlocks(int left[], int right[])
	{
		int res[] = new int[BLOCK_SIZE];
		for(int i = 0; i < BLOCK_SIZE / 2; ++i)
			res[i] = right[i];
		for(int i = BLOCK_SIZE / 2 + 1; i < BLOCK_SIZE; ++i)
			res[i] = left[i];
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

	public int[][] generteKey(int initial_key[]) //all ok
	{
		int key[][] = new int[2][8];
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
		return key;
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

	private int[] encrypt_func(int ara[], int key[])
	{
		int res[] = new int[8];
		int left[] = new int[4];
		int right[] = new int[4];
		int left_xor[] = new int[4];
		int right_xor[] = new int[4];
		int expanded[] = expand(right);
		int xor_res[] = xor(expanded, key);
		for(int i = 0; i < 4; ++i)
			left_xor[i] = xor_res[i];
		for(int i = 4; i < 8; ++i)
			right_xor[i-4] = xor_res[i];
		int s0_res[] = makeS0(left);
		int s1_res[] = makeS1(right);
		int merged = new int[4];
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

	public int[] encrypt(int pt[], key[][])
	{
		int ip_res[] = new int[8];
		ip_res = initPermute(pt);
		
	} 

	public static void main(String args[])
	{
		DataEncryptStd des = new DataEncryptStd();
		int key[] = {1, 0, 1, 0, 0, 0, 0, 0, 1, 0};
		int key_gentd[][] = des.generteKey(key);
		for(int i = 0; i < 2; ++i){
			for(int j = 0; j < 8; ++j)
				System.out.printf("%d ", key_gentd[i][j]);
			System.out.printf("\n");
		}
	}
}