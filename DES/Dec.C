//
// Created by Ashwin S on 11/2/17.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void hexdump_to_string(const void *data, int size, char *str) {
    const unsigned char *byte = (unsigned char *) data;
    while (size > 0) {
        size--;
        sprintf(str, "%.2x ", *byte);
        byte++;
        str += 2;
    }
}

// des encryption/decryption
void des_enc_dec(uint32_t v[2], uint32_t const key[2]);
void ffunction(int* left, int* right, int* key, int* cipher);
void int_to_bin_digit(unsigned int in, int count, int* out);
void keygeneration(int *key , int compkey[16][48]);
void setkey(int* fkey, int round, int compkey[16][48]);
void initialpermutation(int* data, int* completed);
void finalpermutation(int* data, int* completed);
void expansionpermutation(int* right, int* newright);
void pboxpermutation(int *data, int *finaldata);
void sboxsubstituion(int* data, int* newdata);
void binarytohexadecimal(int * data, char* enctext);

char newk[8];
int main(int argc, char **argv) {
    FILE *msg_fp = fopen("message.txt", "r");
    FILE *key_fp = fopen("key.txt", "r");

    // read key from key file
    if (key_fp == NULL)
    {
        printf("Cannot open key file \n");
        exit(0);
    }
    char key[1024];
    int j=0;
    char k;
    while ((k = fgetc(key_fp)) != EOF)
    {
        key[j++] = (char) k;
    }
    key[j] = '\0';
    if(key[j-1] == '\n')
    {
        key[j-1] = '\0';
    }
	j=0;
	while(key[j] != '\0')
	{
		printf("%c", key[j]);
		newk[j] = key[j];
		j++;
	}
	printf("\n");
    // read msg from msg file (msg size will exactly be size of 1 cipher block)
    if (msg_fp == NULL)
    {
        printf("Cannot open message file \n");
        exit(0);
    }
    char msg[1024];
    int i=0;
    char c;
    while ((c = fgetc(msg_fp)) != EOF)
    {
        msg[i++] = (char) c;
    }
    msg[i] = '\0';
    if(msg[i-1] == '\n')
    {
        msg[i-1] = '\0';
    }
	i=0;
	while(msg[i] != '\0')
	{
		printf("%c", msg[i]);
		i++;
	}
	printf("\n");
    // convert key as string to uint32_t
    uint32_t num[2];
    memcpy(num,key,8);
    // printf("%d\n", num[0]);
//     printf("%d\n", num[1]);
    
    int len = strlen(msg);

	uint32_t* message = (uint32_t*)malloc(8*len);
	memcpy(message, msg, len);
	
    // encrypt msg with des using ‘des_enc’ and write encrypted message using ‘hexdump_to_string’ to ‘encrypted_msg.bin’

	// decrypt encrypted msg with des using ‘des_dec’ and write decrypted message to ‘decrypted_msg.txt’
	des_enc_dec(message, num);
	
	fclose(msg_fp);
    fclose(key_fp);
    
    free(message);
    
    return 0;
}

void des_enc_dec(uint32_t v[2], uint32_t const key[2])
{
	char* test = (char*)malloc(8*sizeof(char));
	memcpy(test, v, 8*sizeof(uint32_t));
	int *data = (int*)malloc(64*sizeof(int));
// 	printf("%s\n", test);
	int m=0;
	for (int i = 0; test[i] != '\0'; i++){
//   		printf("%d\n",(int)test[i]);
  		int digit[8];
		int_to_bin_digit((int)test[i], 8, digit);
		for(int j=0;j<8;j++)
		{
// 			printf("%d", digit[j]);
			data[m++] = digit[j];
		}
// 		printf("\n");				
	}
// 	char* newk = (char*)malloc(8*sizeof(char));
// 	memcpy(newk, key, 8*sizeof(uint32_t));
	int *newkey = (int*)malloc(64*sizeof(int));
	int o=0;
	for(int j=0; j<8; j++){
		int keydig[8];
		int_to_bin_digit((int)newk[j], 8, keydig);
		for(int p=0;p<8;p++)
		{
			newkey[o++] = keydig[p];
		}
	}
// 	for(int i=0;i<64;i++)
// 	{
// 	printf("%d", newkey[i]);
// 	}
// 	printf("\n");
	
 	int compkey[16][48];
  	keygeneration(newkey, compkey);
//     
// 	printf("\n");
	int permdata [64];
	printf("Input to Encryption:\n");
	for(int j=0;j<64;j++)
	{
		printf("%d", data[j]);
	}
	initialpermutation(data,permdata);
// 	for(int k=0;k<64;k++)
// 	{
// 		printf("%d", permdata[k]);
// 	}
 	printf("\n");
	int left[32];
	int right[32];
	for(int i=0;i<32;i++)
	{
		left[i] = permdata[i];
		//printf("%d", left[i]);
	}
	//printf("\n");
	int n=0;
	for(int j=32;j<64;j++)
	{
		right[n++] = permdata[j];
		//printf("%d", permdata[j]);
	}
	//printf("\n");
	//printf("\n");
	int fkey[48];
	int cipher[32];
	for(int i=1;i<=16;i++)
	{
		setkey(fkey,i,compkey);
		ffunction(left,right,fkey,cipher);
		memcpy(left,right,32*sizeof(int));
		memcpy(right,cipher,32*sizeof(int));
	}
	int temp[32];
	memcpy(temp, left,32*sizeof(int));
	memcpy(left, right,32*sizeof(int));
	memcpy(right, temp,32*sizeof(int));
	int finalperm[64];
	int finalpermdata[64];
	int q=0;
	for(int i=0;i<32;i++)
	{
		finalperm[q++] = left[i];
		//printf("%d", left[i]);
	}
	//printf("\n");
	for(int i=0;i<32;i++)
	{
		finalperm[q++] = right[i];
		//printf("%d", right[i]);
	}
	//printf("\n");
	finalpermutation(finalperm, finalpermdata);
	printf("Output of Encryption:\n");
	for(int i=0;i<64;i++)
	{
		printf("%d", finalpermdata[i]);
	}
	printf("\n");
	FILE *encrypted_msg_fp = fopen("encrypted_msg.bin", "wb");
	char enctext[16];
	binarytohexadecimal(finalpermdata, enctext);
 	for (int i = 0; i < 16; i++)
	{
    	printf("%c", enctext[i]);
    	fputc(enctext[i], encrypted_msg_fp);
	}
	printf("\n");
	fclose(encrypted_msg_fp);
	
	printf("Input to Decryption:\n");
	for(int i=0;i<32;i++)
	{
		//left[i] = finalpermdata[i];
		printf("%d", finalpermdata[i]);
	}
	//printf("\n");
	//n=0;
	for(int j=32;j<64;j++)
	{
		//right[n++] = finalpermdata[j];
		printf("%d", finalpermdata[j]);
	}
	printf("\n");
	int input[64];
	initialpermutation(finalpermdata, input);
	for(int i=0;i<32;i++)
	{
		left[i] = input[i];
		//printf("%d", left[i]);
	}
	//printf("\n");
	n=0;
	for(int j=32;j<64;j++)
	{
		right[n++] = input[j];
		//printf("%d", finalpermdata[j]);
	}
	//printf("\n");
	for(int i=16;i>=1;i--)
	{
		setkey(fkey,i, compkey);
		ffunction(left,right,fkey,cipher);
		memcpy(left,right,32*sizeof(int));
		memcpy(right,cipher,32*sizeof(int));
	}
	memcpy(temp, left,32*sizeof(int));
	memcpy(left, right,32*sizeof(int));
	memcpy(right, temp,32*sizeof(int));
	int decdata[64];
	m=0;
	for(int i=0;i<32;i++)
	{
		decdata[m++] = left[i];
	}
	for(int j=0;j<32;j++)
	{
		decdata[m++] = right[j];
	}
	int finaldata[64];
	finalpermutation(decdata,finaldata);
	printf("Output of Decryption:\n");
	for(int i=0;i<64;i++)
	{
		printf("%d", finaldata[i]);
	}
	printf("\n");
	uint32_t ascii[8];
	int g=0;
	for(int k=0;k<64;k++)
	{
		ascii[g] = ((finaldata[k]) * (pow(2.0, 7.0)))+((finaldata[k+1])*(pow(2.0, 6.0)))
					+((finaldata[k+2]) * (pow(2.0, 5.0)))+((finaldata[k+3])*(pow(2.0, 4.0)))
					+((finaldata[k+4]) * (pow(2.0, 3.0)))+((finaldata[k+5])*(pow(2.0, 2.0)))
					+((finaldata[k+6]) * (pow(2.0, 1.0)))+((finaldata[k+7])*(pow(2.0, 0.0)));
		k = k+7;
		//printf("%d\n", ascii[g]);
		g += 1;
	}
// 	printf("%s\n", dectext);
	FILE *decrypted_msg_fp = fopen("decrypted_msg.txt", "w");
	char finalstr[8];
	for (int i = 0; i < 8; i++)
	{
    	finalstr[i] = ascii[i];
    	fputc(finalstr[i], decrypted_msg_fp);
    	printf("%c", finalstr[i]);
	}
	printf("\n");
	fclose(decrypted_msg_fp);
	
//free(test);
//free(data);
}

void setkey(int* fkey,int round, int compkey[16][48])
{
	for(int i=0;i<48;i++)
	{
		//printf("%d", compkey[round-1][i]);
		fkey[i] = compkey[round-1][i];
	}
	//printf("\n");
	// int key1[48] = {0,0,0,1,1,0,1,1,0,0,0,0,0,0,1,0,1,1,1,0,1,1,1,1,1,1,1,1,1,1,
//     				0,0,0,1,1,1,0,0,0,0,0,1,1,1,0,0,1,0};
//  	int key2[48] = {0,1,1,1,1,0,0,1,1,0,1,0,1,1,1,0,1,1,0,1,1,0,0,1,1,1,0,1,1,0,
//  					1,1,1,1,0,0,1,0,0,1,1,1,1,0,0,1,0,1};
//  	int key3[48] = {0,1,0,1,0,1,0,1,1,1,1,1,1,1,0,0,1,0,0,0,1,0,1,0,0,1,0,0,0,0,
//  					1,0,1,1,0,0,1,1,1,1,1,0,0,1,1,0,0,1};
//  	int key4[48] = {0,1,1,1,0,0,1,0,1,0,1,0,1,1,0,1,1,1,0,1,0,1,1,0,1,1,0,1,1,0,
//  					1,1,0,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1};
//  	int key5[48] = {0,1,1,1,1,1,0,0,1,1,1,0,1,1,0,0,0,0,0,0,0,1,1,1,1,1,1,0,1,0,
//  					1,1,0,1,0,1,0,0,1,1,1,0,1,0,1,0,0,0};
//  	int key6[48] = {0,1,1,0,0,0,1,1,1,0,1,0,0,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,0,0,
//  					0,0,0,1,1,1,1,0,1,1,0,0,1,0,1,1,1,1};
//  	int key7[48] = {1,1,1,0,1,1,0,0,1,0,0,0,0,1,0,0,1,0,1,1,0,1,1,1,1,1,1,1,0,1,
//  					1,0,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,0};
//  	int key8[48] = {1,1,1,1,0,1,1,1,1,0,0,0,1,0,1,0,0,0,1,1,1,0,1,0,1,1,0,0,0,0,
//  					0,1,0,0,1,1,1,0,1,1,1,1,1,1,1,0,1,1};
//  	int key9[48] = {1,1,1,0,0,0,0,0,1,1,0,1,1,0,1,1,1,1,1,0,1,0,1,1,1,1,1,0,1,1,
//  					0,1,1,1,1,0,0,1,1,1,1,0,0,0,0,0,0,1};
//  	int key10[48] = {1,0,1,1,0,0,0,1,1,1,1,1,0,0,1,1,0,1,0,0,0,1,1,1,1,0,1,1,1,0,
//  					1,0,0,1,0,0,0,1,1,0,0,1,0,0,1,1,1,1};
//  	int key11[48] = {0,0,1,0,0,0,0,1,0,1,0,1,1,1,1,1,1,1,0,1,0,0,1,1,1,1,0,1,1,1,
//  					1,0,1,1,0,1,0,0,1,1,1,0,0,0,0,1,1,0};
//  	int key12[48] = {0,1,1,1,0,1,0,1,0,1,1,1,0,0,0,1,1,1,1,1,0,1,0,1,1,0,0,1,0,1,
//  					0,0,0,1,1,0,0,1,1,1,1,1,1,0,1,0,0,1};
//  	int key13[48] = {1,0,0,1,0,1,1,1,1,1,0,0,0,1,0,1,1,1,0,1,0,0,0,1,1,1,1,1,1,0,
//  					1,0,1,0,1,1,1,0,1,0,0,1,0,0,0,0,0,1};
//  	int key14[48] = {0,1,0,1,1,1,1,1,0,1,0,0,0,0,1,1,1,0,1,1,0,1,1,1,1,1,1,1,0,0,
//  					1,0,1,1,1,0,0,1,1,1,0,0,1,1,1,0,1,0};
//  	int key15[48] = {1,0,1,1,1,1,1,1,1,0,0,1,0,0,0,1,1,0,0,0,1,1,0,1,0,0,1,1,1,1,
//  					0,1,0,0,1,1,1,1,1,1,0,0,0,0,1,0,1,0};
//  	int key16[48] = {1,1,0,0,1,0,1,1,0,0,1,1,1,1,0,1,1,0,0,0,1,0,1,1,0,0,0,0,1,1,
//  					1,0,0,0,0,1,0,1,1,1,1,1,1,1,0,1,0,1};
//  					
//  	if(round == 1)
//  	{
//  		memcpy(fkey,key1,48*sizeof(int));
//  	}
//  	else if(round == 2)
//  	{
//  		memcpy(fkey,key2,48*sizeof(int));
//  	}
//  	else if(round == 3)
//  	{
//  		memcpy(fkey,key3,48*sizeof(int));
//  	}
//  	else if(round == 4)
//  	{
//  		memcpy(fkey,key4,48*sizeof(int));
//  	}
//  	else if(round == 5)
//  	{
//  		memcpy(fkey,key5,48*sizeof(int));
//  	}
//  	else if(round == 6)
//  	{
//  		memcpy(fkey,key6,48*sizeof(int));
//  	}
//  	else if(round == 7)
//  	{
//  		memcpy(fkey,key7,48*sizeof(int));
//  	}
//  	else if(round == 8)
//  	{
//  		memcpy(fkey,key8,48*sizeof(int));
//  	}
//  	else if(round == 9)
//  	{
//  		memcpy(fkey,key9,48*sizeof(int));
//  	}
//  	else if(round == 10)
//  	{
//  		memcpy(fkey,key10,48*sizeof(int));
//  	}
//  	else if(round == 11)
//  	{
//  		memcpy(fkey,key11,48*sizeof(int));
//  	}
//  	else if(round == 12)
//  	{
//  		memcpy(fkey,key12,48*sizeof(int));
//  	}
//  	else if(round == 13)
//  	{
//  		memcpy(fkey,key13,48*sizeof(int));
//  	}
//  	else if(round == 14)
//  	{
//  		memcpy(fkey,key14,48*sizeof(int));
//  	}
//  	else if(round == 15)
//  	{
//  		memcpy(fkey,key15,48*sizeof(int));
//  	}
//  	else
//  	{
//  		memcpy(fkey,key16,48*sizeof(int));
//  	} 					
}

void ffunction(int* left, int* right, int* key, int* cipher)
{
	int newright[48];
	int xored[48];
	expansionpermutation(right,newright);
	for(int i=0;i<48;i++)
	{
		xored[i] = key[i]^newright[i];
	}
	int sboxeddata[32];
	sboxsubstituion(xored,sboxeddata);
	int pboxed[32];
	pboxpermutation(sboxeddata, pboxed);
	for(int i=0;i<32;i++)
	{
		cipher[i] = pboxed[i]^left[i];
	}
}

void int_to_bin_digit(unsigned int in, int count, int* out)
{
    unsigned int mask = 1U << (count-1);
    int i;
    for (i = 0; i < count; i++) {
        out[i] = (in & mask) ? 1 : 0;
        in <<= 1;
    }
}

void binarytohexadecimal(int * data, char* enctext)
{
	int decimal[16];
	int g=0;
	for(int i=0;i<64;i++)
	{
		decimal[g] = ((data[i]) * (pow(2.0, 3.0)))+((data[i+1])*(pow(2.0, 2.0)))
					+((data[i+2]) * (pow(2.0, 1.0)))+((data[i+3])*(pow(2.0, 0.0)));
		if(decimal[g] == 10)
			enctext[g] = 'a';
		else if(decimal[g] == 11)
			enctext[g] = 'b';
		else if(decimal[g] == 12)
			enctext[g] = 'c';
		else if(decimal[g] == 13)
			enctext[g] = 'd';
		else if(decimal[g] == 14)
			enctext[g] = 'e';
		else if(decimal[g] == 15)
			enctext[g] = 'f';
		else
			enctext[g] = decimal[g] + '0';
			
		g=g+1;
		i=i+3;
	}
}

void keygeneration(int *key , int compkey[16][48])
{
	int dropped[56];
	int k=0;
	int length=0;
	for(int i=0; i<64; i++)
	{
		if(length==7)
		{
			length=0;
		}
		else
		{
			dropped[k++] = key[i];
			length += 1;
		}
	}
	int newkey[56];
	for(int m=0;m<56;m++)
	{
		newkey[m] = dropped[m];
		//printf("%d",newkey[m]);
	}
	//printf("\n");
	int parity[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,
					60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,
					29,21,13,5,28,20,12,4};
	int keycomp[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
				 41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
	
	int paritydone[56];
	for(int i=0;i<56;i++)
	{
		paritydone[i] = newkey[parity[i]-1];
		//printf("%d", paritydone[i]);
	}
	//printf("\n");
	
	for(int round=1;round<=16;round++)
	{
		int leftparity[28];
		int rightparity[28];
		for(int j=0;j<28;j++)
		{
			leftparity[j] = paritydone[j];
		}
		int f=0;
		for(int j=28;j<56;j++)
		{
			rightparity[f++] = paritydone[j];
		}
		int newleft[28];
		int newright[28];
		if(round == 1 || round ==2 || round ==9 || round ==16)
		{
			for(int i=0 ;i<28;i++)
			{
				if(i == 27)
				{
					newleft[i] = leftparity[0];
				}
				else
					newleft[i] = leftparity[i+1];
			}
			for(int i=0 ;i<28;i++)
			{
				if(i == 27)
				{
					newright[i] = rightparity[0];
				}
				else
					newright[i] = rightparity[i+1];
			}
		}
		else
		{
			for(int i=0 ;i<28;i++)
			{
				if(i == 27)
					newleft[i] = leftparity[1];
				else if(i ==26)
					newleft[i] = leftparity[0];
				else
					newleft[i] = leftparity[i+2];
			}
			for(int i=0 ;i<28;i++)
			{
				if(i == 27)
					newright[i] = rightparity[1];
				else if(i ==26)
					newright[i] = rightparity[0];
				else
					newright[i] = rightparity[i+2];
			}
		}
		for(int j=0;j<28;j++)
		{
			paritydone[j] = newleft[j];
		}
		int h=0;
		for(int j=28;j<56;j++)
		{
			paritydone[j] = newright[h++];
		}
		for(int j=0;j<48;j++)
		{
			compkey[round-1][j] = paritydone[keycomp[j]-1];
			//printf("%d", compkey[round-1][j]);
		}
		//printf("\n");
	}	

}

void initialpermutation(int* data, int* completed)
{
	int initial[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,
					64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
					61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
					
// 	for(int k=0;k<64;k++)
// 	{
// 		printf("%d", data[k]);
// 	}
// 	printf("\n");
	for(int k=0;k<64;k++)
	{
		completed[k] = data[initial[k]-1];
// 		printf("%d", completed[k]);
	}
// 	printf("\n");
}

void finalpermutation(int* data, int* completed)
{
	int final[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,
					 30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,
					 59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
	
	// for(int k=0;k<64;k++)
// 	{
// 		printf("%d", data[k]);
// 	}
// 	printf("\n");
	for(int k=0;k<64;k++)
	{
		completed[k] = data[final[k]-1];
// 		printf("%d", completed[k]);
	}
// 	printf("\n");
}

void expansionpermutation(int* right, int* newright)
{
	int expandr[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,
						18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
		
	for(int i=0;i<48;i++)
	{
		newright[i] = right[expandr[i]-1];
	}
}

void pboxpermutation(int *data, int *finaldata)
{
	int pbox[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,
					2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
	
	for(int i=0;i<32;i++)
	{
		finaldata[i] = data[pbox[i]-1];
	}
}

void sboxsubstituion(int* data, int* newdata)
{
	int finalsbox[32];
	int k=0;
	int sbox1[4][16]={{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
					  {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
					  {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
					  {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}};
	int sbox2[4][16]={{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
					  {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
					  {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
					  {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}};
	int sbox3[4][16]={{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
				 	  {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
				 	  {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
				 	  {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}};	  
	int sbox4[4][16]={{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
					  {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
					  {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
					  {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}};
	int sbox5[4][16]={{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
					  {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
					  {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
					  {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}};
	int sbox6[4][16]={{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
					  {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
					  {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
					  {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}};
	int sbox7[4][16]={{4,11,2,14,15,0,8,13,3,12,9,7,6,10,6,1},
					  {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
					  {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
					  {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}};
	int sbox8[4][16]={{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
					  {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
					  {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
					  {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};
				
	int row = ((data[0])* (pow(2.0, 1.0)))+((data[5])*(pow(2.0, 0.0)));
// 	printf("%d\n", row);
	int column = ((data[1])* (pow(2.0, 3.0)))+((data[2])*(pow(2.0, 2.0)))
				+ ((data[3])* (pow(2.0, 1.0))) +((data[4])* (pow(2.0, 0.0)));
// 	printf("%d\n",column);
	int final = sbox1[row][column];
// 	printf("%d\n", final);
	int digit[4];
	int_to_bin_digit(final, 4, digit);
	for(int j=0;j<4;j++)
	{
// 		printf("%d", digit[j]);
		finalsbox[k++] = digit[j];
	}
// 	printf("\n");
		
	row = ((data[6])* (pow(2.0, 1.0)))+((data[11])*(pow(2.0, 0.0)));
	column = ((data[7])* (pow(2.0, 3.0)))+((data[8])*(pow(2.0, 2.0)))
				+ ((data[9])* (pow(2.0, 1.0))) +((data[10])* (pow(2.0, 0.0)));
	final = sbox2[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	row = ((data[12])* (pow(2.0, 1.0)))+((data[17])*(pow(2.0, 0.0)));
	column = ((data[13])* (pow(2.0, 3.0)))+((data[14])*(pow(2.0, 2.0)))
				+ ((data[15])* (pow(2.0, 1.0))) +((data[16])* (pow(2.0, 0.0)));
	final = sbox3[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	row = ((data[18])* (pow(2.0, 1.0)))+((data[23])*(pow(2.0, 0.0)));
	column = ((data[19])* (pow(2.0, 3.0)))+((data[20])*(pow(2.0, 2.0)))
				+ ((data[21])* (pow(2.0, 1.0))) +((data[22])* (pow(2.0, 0.0)));
	final = sbox4[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	row = ((data[24])* (pow(2.0, 1.0)))+((data[29])*(pow(2.0, 0.0)));
	column = ((data[25])* (pow(2.0, 3.0)))+((data[26])*(pow(2.0, 2.0)))
				+ ((data[27])* (pow(2.0, 1.0))) +((data[28])* (pow(2.0, 0.0)));
	final = sbox5[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	row = ((data[30])* (pow(2.0, 1.0)))+((data[35])*(pow(2.0, 0.0)));
	column = ((data[31])* (pow(2.0, 3.0)))+((data[32])*(pow(2.0, 2.0)))
				+ ((data[33])* (pow(2.0, 1.0))) +((data[34])* (pow(2.0, 0.0)));
	final = sbox6[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	row = ((data[36])* (pow(2.0, 1.0)))+((data[41])*(pow(2.0, 0.0)));
	column = ((data[37])* (pow(2.0, 3.0)))+((data[38])*(pow(2.0, 2.0)))
				+ ((data[39])* (pow(2.0, 1.0))) +((data[40])* (pow(2.0, 0.0)));
	final = sbox7[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	row = ((data[42])* (pow(2.0, 1.0)))+((data[47])*(pow(2.0, 0.0)));
	column = ((data[43])* (pow(2.0, 3.0)))+((data[44])*(pow(2.0, 2.0)))
				+ ((data[45])* (pow(2.0, 1.0))) +((data[46])* (pow(2.0, 0.0)));
	final = sbox8[row][column];
	int_to_bin_digit(final, 4, digit);	
	for(int j=0;j<4;j++)
	{		
		finalsbox[k++] = digit[j];
	}
	
	for(int l=0;l<32;l++)
	{
		newdata[l] = finalsbox[l];
	}
	
}

