#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define _CRT_SECURE_NO_WARNINGS

#define __be32 unsigned int
#define u32 unsigned int

unsigned int swap(unsigned int x) {
	unsigned char* t0 = (unsigned char*)&x;
	unsigned ret = 0;
	unsigned char* t1 = (unsigned char*)&ret;
	for (int i = 0; i < 4; i++) {
		t1[i] = t0[3 - i];
	}
	return ret;
}

#define GOLDEN_RATIO_PRIME_32 0x9e370001UL
static inline u32 hash_32(u32 val, unsigned int bits)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	u32 hash = val * GOLDEN_RATIO_PRIME_32;

	/* High bits are more random, so use them. */
	return hash >> (32 - bits);
}


static inline u32 rol32(u32 word, unsigned int shift)
{
	return (word << shift) | (word >> (32 - shift));
}

#define JHASH_INITVAL		0xdeadbeef

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

static inline u32 jhash_3words(u32 a, u32 b, u32 c, u32 initval)
{
	a += JHASH_INITVAL;
	b += JHASH_INITVAL;
	c += initval;

	__jhash_final(a, b, c);

	return c;
}

static inline u32 jhash_1word(u32 a, u32 initval)
{
	return jhash_3words(a, 0, 0, initval);
}
#define FNHE_HASH_SHIFT		11
static inline u32 fnhe_hashfun(__be32 daddr, u32 fnhe_hashrnd)
{
	u32 hval;

	hval = jhash_1word((u32) daddr, fnhe_hashrnd);
	return hash_32(hval, FNHE_HASH_SHIFT);
}

unsigned char testedIP[5000][4];
int testedIPCount = 0; //input
unsigned int removedIPNum[20];
int removedIPCount = 0; //input

// probably race condition here
unsigned int results[20];
int resultCount = 0; //output
int finished[12]; //in and output


//(gdb) print seed
//$1 = 0xdeadbeef
void guess_seed3(int tasknum, int totalNum) {
	unsigned int total_task = 0xffffffff;
	unsigned int start = 0x0000 + total_task / totalNum * tasknum;
	unsigned int end = 0x0000 + total_task / totalNum * (tasknum + 1);
	printf("Seed guessing %u(%uM)-%u(%uM) begin\n", start, start / 1000000, end, end / 1000000);
	for (unsigned int seed = start; seed < end; seed++) {
		//		if (seed % 10000000 == 0) {
		//			printf("%u: %u/%u (%.2f)\n", tasknum, (seed - start) / 1000000, (end - start) / 1000000, ((float)(seed - start)) / (end - start));
		//		}
		int bucket[2048][6];
		int bucketPtr[2048];
		memset(bucket, -1, 2048 * 6 * sizeof(int));
		memset(bucketPtr, 0, 2048 * sizeof(int));
		unsigned int currentRemovedIPNum[20];
		int currentRemovedIPCount = 0;
		int currentRemovedIPFull = 0;

		for (int i = 0; i < testedIPCount; i++) {
			int slot = fnhe_hashfun(*(__be32*)(testedIP[i]), seed);
			int foundSlot = 0;
			if (currentRemovedIPFull) {
				break;
			}
			int bucketSlot = bucketPtr[slot];
			if (bucketSlot < 6) {
				bucket[slot][bucketSlot] = i;
				foundSlot = 1;
				bucketPtr[slot]++;
			}
			//			for (int j = 0; j < 6; j++) {
			//				if (bucket[slot][j] == -1) {
			//					bucket[slot][j] = i;
			//					foundSlot = 1;
			//					break;
			//				}
			//			}
			if (!foundSlot) {
				if (currentRemovedIPCount == removedIPCount) {
					currentRemovedIPFull = 1;
					break;
				}
				currentRemovedIPNum[currentRemovedIPCount++] = bucket[slot][0];
				int foundMatch = 0;
				for (int l = 0; l < removedIPCount; l++) {
					if (removedIPNum[l] == bucket[slot][0]) {
						foundMatch = 1;
						break;
					}
				}
				if (!foundMatch) {
					break;
				}
				//printf("removed: %d.%d.%d.%d@bkt %d\n", testedIP[bucket[slot][0]][0], testedIP[bucket[slot][0]][1], testedIP[bucket[slot][0]][2], testedIP[bucket[slot][0]][3], slot);
				for (int k = 1; k < 6; k++) {
					bucket[slot][k - 1] = bucket[slot][k];
				}
				bucket[slot][5] = i;
			}
		}

		if (!currentRemovedIPFull && currentRemovedIPCount == removedIPCount) {
			unsigned int originalSum = 0;
			unsigned int newSum = 0;
			for (int i = 0; i < removedIPCount; i++) {
				originalSum += removedIPNum[i];
				newSum += currentRemovedIPNum[i];
			}
			if (originalSum == newSum) {
				// sync problem?
				results[resultCount++] = seed;
				printf("seed=%u\n", seed);
			}
			if (resultCount == 10) {
				break;
			}
		}
	}
	//	finished[tasknum] = 1;
}

void guess_seed3_input(int argc, char** argv) {
	if (argc < 4) {
		printf("argc < 4, error\n");
		return;
	}
	int tasknum = atoi(argv[1]);
	int totalNum = atoi(argv[2]);
	FILE* f = fopen(argv[3], "r");
	if (f == 0) {
		printf("file open err, exiting...\n");
		return;
	}
	// testedIPCount
	fscanf(f, "%d", &testedIPCount);
	// n tested IP: de ad be ff
	for (int i = 0; i < testedIPCount; i++) {
		for (int j = 0; j < 4; j++) {
			fscanf(f, "%x", &testedIP[i][j]);
		}
	}
	// removedIPCount
	fscanf(f, "%d", &removedIPCount);
	// m removedIP: 1 2 3
	for (int i = 0; i < removedIPCount; i++) {
		fscanf(f, "%d", &removedIPNum[i]);
	}
	fclose(f);

	// multi-processing
	guess_seed3(tasknum, totalNum);

	printf("seeds=");
	for (int i = 0; i < resultCount; i++) {
		printf("%x ", results[i]);
	}
	printf("\n");

}

int main(int argc, char** argv) {

	guess_seed3_input(argc, argv);
	return 0;

}

