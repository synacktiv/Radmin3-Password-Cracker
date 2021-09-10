/*
 * BF hash passwords for radmin
 * g++ -o radmin3_bf -O0 -ggdb -fsanitize=address -fno-omit-frame-pointer radmin3_bf.c -lssl -lcrypto -lpthread
 * g++ -o radmin3_bf -O3 radmin3_bf.c -lssl -lcrypto -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h> 
#include <unistd.h> 

#define GENERATOR_HEXSTR "5"
#define SALT_HEXSTR "16257c8778bc06b36d358a2158eb2689f484d0a25742050c5badef0af3a6d283"
#define MODULUS_HEXSTR "9847fc7e0f891dfd5d02f19d587d8f77aec0b980d4304b0113b406f23e2cec58cafca04a53e36fb68e0c3bff92cf335786b0dbe60dfe4178ef2fcd2a4dd09947ffd8df96fd0f9e2981a32da95503342eca9f08062cbdd4ac2d7cdf810db4db96db70102266261cd3f8bdd56a102fc6ceedbba5eae99e6127bdd952f7a0d18a79021c881ae63ec4b3590387f548598f2cb8f90dea36fc4f80c5473fdb6b0c6bdb0fdbaf4601f560dd149167ea125db8ad34fd0fd45350dec72cfb3b528ba2332d6091acea89dfd06c9c4d18f697245bd2ac9278b92bfe7dbafaa0c43b40a71f1930ebc4fd24c9e5a2e5a4ccf5d7f51544d70b2bca4af5b8d37b379fd7740a682f"
#define VERIFIER_HEXSTR "1aea28ecfa04940964396bfdb2f3e2021c761982d198baabe7668fdf661be1b03653bd2a69241710f1cc492cf7f47a453ea6c0c7dfb25327e2c07ba9b5c68130eeff5b15c5df1d87f4a3d9675a6ff19430eab76fffb16855b58372d8d5cfbf422a67d304e5586017b89e52c9176664eb61fed2a4d43ca4d9fc33cd7e8ab015764e6a3894afadebf987db36e1b0487b83598602b49c91e26b51ccd89c719cf9644f89fae5a69f7b4dc73ac5e8b7ebf1e02e7c497359207f241431fc257c5c995699a4ccb626d015859a7027aafdf008044ec70521def1d59c43dde0644777dc51bb39175920a0f6040d9167f68569573b70390c729ad430d66e779ab81cb1a88a"
unsigned char username[] = "jonathan";

#define CHUNK_LEN 16 // Higher value -> Bigger cache, more expensive to compute, but faster crack time
					 // Must divide 160 (SHA1 size in bits)
#define CHUNK_NUM (160/CHUNK_LEN)
#define CHUNK_POP (1<<CHUNK_LEN)

#define NUM_THREADS 8
#define BATCH_SIZE 10000

/* NO CHANGING BELOW */

char batch_buffers[NUM_THREADS][BATCH_SIZE][0x100];
unsigned char active_threads[NUM_THREADS];
pthread_t threads[NUM_THREADS];
char was_password_found;
char found_password[256];

struct timeval stop, start;

static size_t size_username = sizeof(username)-1;

BIGNUM* cache[160];
BIGNUM* bigcache[160/CHUNK_LEN*CHUNK_POP];

BN_MONT_CTX* thread_mont_ctx[NUM_THREADS];
BN_CTX *thread_ctx[NUM_THREADS];

unsigned char *salt;
size_t size_salt;
BIGNUM *hash;
BIGNUM *modulus;
BIGNUM *base;


// Cache values for faster mod_exp
static void cache_exp(BIGNUM *base,BIGNUM *modulus,BN_CTX *ctx, BN_MONT_CTX *mont_ctx)
{
	BIGNUM *TWO = BN_new();
	unsigned int two = htonl(2);
	BN_bin2bn( (unsigned char *) &two, sizeof(two), TWO);
	
	BIGNUM *x = BN_new();
	BIGNUM *I = BN_new();

	for(unsigned int i=0;i<160;i++)
	{
		BIGNUM *c = BN_new();

		unsigned int ii = htonl(i);
		BN_bin2bn( (unsigned char *) &ii, sizeof(ii), I);
		
		
		BN_mod_exp(x, TWO, I, modulus, ctx);

		if (!BN_mod_exp(c, base, x, modulus, ctx)) {
			printf("Failed to compute mod mul cache\n");
			exit(0);
		}
		BN_to_montgomery(c,c,mont_ctx,ctx);

		cache[i]=c;

	}
	BN_free(x);
	BN_free(I);
}

//Faster mod_exp
static int custom_exp(
		BIGNUM *out,
		BIGNUM *base,
		BIGNUM *x,
		BIGNUM *modulus,
		BN_CTX *ctx, BN_MONT_CTX *mont_ctx) {
	
	unsigned int one = htonl(1);
	BN_bin2bn( (unsigned char *) &one, sizeof(one), out);

	BN_to_montgomery(out,out,mont_ctx,ctx);

	for(int i=0;i<160;i++)
	{
		if(BN_is_bit_set(x, i))
		{
			BN_mod_mul_montgomery(out,out,cache[i],mont_ctx,ctx); 
		}
	}
	BN_from_montgomery(out,out,mont_ctx,ctx);

	return 0;
}

static BIGNUM* MIL;
// Cache more values for even faster mod_exp
static void bigcache_exp(BIGNUM *base,BIGNUM *modulus,BN_CTX *ctx, BN_MONT_CTX *mont_ctx)
{
	BIGNUM *J = BN_new();
	for(unsigned int i=0;i<CHUNK_NUM;i++)
	{
		printf("Building big cache %d / %d...\n",i+1,CHUNK_NUM);
		for(unsigned int j=0;j<CHUNK_POP;j++)
		{
			BIGNUM *c = BN_new();
			

			unsigned int jj = htonl(j);
			BN_bin2bn( (unsigned char *) &jj, sizeof(jj), J);
			
			BN_lshift(J,J,(CHUNK_NUM-1-i)*CHUNK_LEN);
			
			custom_exp(c,base,J,modulus,ctx,mont_ctx);

			BN_to_montgomery(c,c,mont_ctx,ctx);

			bigcache[i*CHUNK_POP+j]=c;
			
		}
	}
	BN_free(J);
	MIL = BN_new();
	unsigned int mil = htonl(CHUNK_POP);
	BN_bin2bn( (unsigned char *) &mil, sizeof(mil), MIL);
}

// Even faster mod_exp
static int custom_exp2(
		BIGNUM *out,
		BIGNUM *base,
		BIGNUM *x,
		BIGNUM *modulus,
		BN_CTX *ctx,
		BN_MONT_CTX *mont_ctx) {
	
	unsigned int one = htonl(1);
	BN_bin2bn( (unsigned char *) &one, sizeof(one), out);

	BN_to_montgomery(out,out,mont_ctx,ctx);

	unsigned int idx;
	BIGNUM *xc = BN_new();
	for(int i=0;i<CHUNK_NUM;i++)
	{
		
		BN_rshift(xc,x,160-((i+1)*CHUNK_LEN));
		BN_mod(xc,xc,MIL,ctx);
		
		BN_bn2binpad(xc, (unsigned char *)&idx, 4);
		
		idx = htonl(idx);
		BN_mod_mul_montgomery(out,out,bigcache[i*CHUNK_POP+idx],mont_ctx,ctx);
	}
	BN_free(xc);
	BN_from_montgomery(out,out,mont_ctx,ctx);

	return 0;
}

static int test_password(
		unsigned char* const passwd,
		unsigned char* const salt, size_t size_salt,
		BIGNUM *modulus,
		BIGNUM *base,
		BIGNUM *hash,
		BN_CTX *ctx,
		BN_MONT_CTX *mont_ctx) {

	// first hash
	unsigned char concat[254];
	unsigned char sha1sum[SHA_DIGEST_LENGTH];
	// second hash
	unsigned char concat2[size_salt + SHA_DIGEST_LENGTH];
	unsigned char sha1sum2[SHA_DIGEST_LENGTH];
	
	size_t len_username = strlen((char* const) username);
	size_t len_passwd = strlen((char* const) passwd);
	size_t size_concat = sizeof(concat)/sizeof(concat[0]);
	size_t final_len;

	// first hash: fill the buffer with the username and ':'
	memset(concat, 0x00, 254);

	// first hash: append the username (utf16)
	int j = 0;
	for (final_len = 0; final_len + 1 < size_concat && j < len_username; final_len += 2)
		concat[final_len] = username[j++];

	concat[len_username*2]=':';
	// first hash: append the password (utf16)
	j = 0;
	for (final_len = len_username*2+1; final_len + 1 < size_concat && j < len_passwd; final_len += 2)
		concat[final_len] = passwd[j++];

	if (final_len + 1 >= size_concat || j > len_passwd)
		return 2; // we exhausted the buffer's size

	// first hash: hash it out
	unsigned char *res = SHA1((unsigned char* const)concat, final_len, sha1sum);

	// second hash: prepend the result with the salt
	memcpy(concat2, salt, size_salt);
	memcpy(concat2 + size_salt, sha1sum, SHA_DIGEST_LENGTH);

	// second hash: hash it out again
	unsigned char *res2 = SHA1(concat2, size_salt + SHA_DIGEST_LENGTH, sha1sum2);

	// convert second hash to bignum
	BIGNUM *x = BN_bin2bn(sha1sum2, SHA_DIGEST_LENGTH, NULL);
	if (x == 0) {
		printf("Failed to convert result of sha to BIGNUM");
		return 1;
	}

	// pow mod
	BIGNUM *res3 = BN_new();

	if(0) // Initial approach
	{
		if (!BN_mod_exp(res3, base, x, modulus, ctx)) {
			printf("Failed to compute mod mul\n");
			return 1;
		}
	}
	else // 5 times faster !
	{
		custom_exp2(res3,base,x,modulus,ctx,mont_ctx);
	}

	// is this it?
	int found = BN_cmp(hash, res3) == 0;

	// cleanup
	BN_free(x);
	BN_free(res3);

	return found;
}



void* process_batch(void* arg){
  
	int thread_num = *(int*)arg;
	free(arg);
	for(int i=0; i<BATCH_SIZE; i+=1)
	{
		if(was_password_found)break;
		if(strlen(batch_buffers[thread_num][i])>0)
		{
			if (test_password((unsigned char*) (batch_buffers[thread_num][i]), salt, size_salt, modulus, base, hash, thread_ctx[thread_num], thread_mont_ctx[thread_num]) == 1) {
				strncpy(found_password,batch_buffers[thread_num][i],256);
				was_password_found = 1;
				break;
			}
		}
	}

	active_threads[thread_num]=0;
	void* dummy;
	pthread_exit(dummy);
}

int main(int argc, char **argv) {

	if (argc < 2) {
		printf("usage: %s wordlist.txt\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char *wordlist = argv[1];

	BN_MONT_CTX *mont_ctx;
	BN_CTX *ctx;


	if (BN_hex2bn(&hash, VERIFIER_HEXSTR) == 0) {
		printf("Failed to convert hash hexstring to BIGNUM\n"); return 1;
	}
	
	if (BN_hex2bn(&modulus, MODULUS_HEXSTR) == 0) {
		printf("Failed to convert modulus hexstring to BIGNUM\n"); return 1;
	}
	
	if (BN_hex2bn(&base, GENERATOR_HEXSTR) == 0) {
		printf("Failed to convert base hexstring to BIGNUM\n"); return 1;
	}

	salt = OPENSSL_hexstr2buf(SALT_HEXSTR, NULL);
	size_salt = strlen(SALT_HEXSTR) / 2;

	FILE *fp;
	char *c = NULL;
	size_t len = 0;
	ssize_t read;

	if (wordlist[0] == '-' && wordlist[1] == '\x00') {
		// use stdin
		fp = stdin;

	} else if ((fp = fopen(wordlist, "r")) == NULL) {
			printf("Could not read wordlist '%s'\n", wordlist);
			exit(EXIT_FAILURE);
	}


	ctx = BN_CTX_new();
	mont_ctx = BN_MONT_CTX_new();
	BN_MONT_CTX_set(mont_ctx,modulus,ctx);
	for(int thread_num=0; thread_num<NUM_THREADS; thread_num++)
	{
		threads[thread_num] = -1;
		active_threads[thread_num] = 0;
		thread_ctx[thread_num] = BN_CTX_new();
		thread_mont_ctx[thread_num] = BN_MONT_CTX_new();
		BN_MONT_CTX_set(thread_mont_ctx[thread_num],modulus,thread_ctx[thread_num]);
	}
	was_password_found=0;
	memset(found_password,0,256);

	cache_exp(base,modulus,ctx,mont_ctx);
	bigcache_exp(base,modulus,ctx,mont_ctx);

	int i = 0;

	gettimeofday(&start, NULL);

	unsigned long long total_processed = 0;
	unsigned char over = 0;
	while(!over)
	{
		for(long long thread_num=0; thread_num<NUM_THREADS; thread_num++)
		{
			if(was_password_found || over)
			{
				over = 1;
				break;
			}
			if(!active_threads[thread_num])
			{
				if(threads[thread_num]!=-1)
				{
					void* dummy;
					pthread_join(threads[thread_num],&dummy);
					threads[thread_num]=0;
					total_processed+=BATCH_SIZE;
					printf("Processed %lld candidates\n", total_processed);
				}
				for(int i=0;i<BATCH_SIZE;i++)
				{
					memset(batch_buffers[thread_num][i],0,256);
				}
				int idx = 0;
				while(idx<BATCH_SIZE)
				{
					read = getline(&c, &len, fp);
					if(read == -1)
					{
						over = 1;
						break;
					}
					c[read-1] = '\x00'; // dirty trim '\n'
					if(read>256)continue;
					strncpy(batch_buffers[thread_num][idx],c,256);
					idx+=1;
				}

				void *arg = malloc(sizeof(int));
				*(int*)arg = thread_num;
				pthread_create(&threads[thread_num], NULL, process_batch, arg);
			}
		}
		usleep(1000);
	}

	for(int thread_num=0; thread_num<NUM_THREADS; thread_num++)
	{
		if(threads[thread_num]!=-1)
		{
			void* dummy;
			pthread_join(threads[thread_num], &dummy);
			threads[thread_num]=0;
		}
		
	}

	if(was_password_found)
	{
		printf("\n\nFound password : %s\n\n", &found_password);
	}
	else
	{
		printf("\n\nNo password found.\n\n");
	}
	

	gettimeofday(&stop, NULL);
	printf("took %lu ms\n", (stop.tv_sec - start.tv_sec) * 1000 + (stop.tv_usec - start.tv_usec)/1000); 

	BN_free(hash);
	BN_free(modulus);
	BN_free(base);
	BN_MONT_CTX_free(mont_ctx);
	BN_CTX_free(ctx);
	for(int thread_num=0; thread_num<NUM_THREADS; thread_num++)
	{
		BN_MONT_CTX_free(thread_mont_ctx[thread_num]);
		BN_CTX_free(thread_ctx[thread_num]);
	}
	OPENSSL_free(salt);
	
	return 0;
}
