// gcc brute.c -lssl -lcrypto
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#define HASH_LEN SHA_DIGEST_LENGTH
#define DATA_LEN 21
#define BRUTE_LEN 5
#define MAX ((unsigned long long)1 << (BRUTE_LEN*8))

void bindump(unsigned char* tb, int len) {
  int i;
  if (tb != NULL)
    for (i=0; i<len; i++)
      printf("%02x", tb[i]);
  printf("\n");
}

void brute_hash(const char *condition) {
  unsigned long long i;
  unsigned char buffer[256];
  unsigned char hash[HASH_LEN];

  for (i=0; i<MAX; i++) {
    memcpy(buffer, condition, DATA_LEN - BRUTE_LEN);
    memcpy(&buffer[DATA_LEN - BRUTE_LEN], (unsigned char*)&i, BRUTE_LEN);
    SHA1(buffer, DATA_LEN, hash);

    if (!memcmp(&hash[HASH_LEN-strlen("\xff\xff")], "\xff\xff", strlen("\xff\xff"))) {
      bindump(buffer, DATA_LEN);
      exit(0);
    }
  }
}

int main(int argc, char** argv){
  if (argc > 1)
    brute_hash(argv[1]);
  return 0;
}

/*
root@Ubuntu64:/tmp# ./a.out '2W4IkTCSB52+EhJi'
325734496b5443534235322b45684a69743f010000
root@Ubuntu64:/tmp# py
>>> import hashlib
>>> hashlib.sha1('325734496b5443534235322b45684a69743f010000'.decode("hex")).hexdigest()
'840019c730002de4102fc6cd89c39cc77c35ffff'
*/
