#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

/*
NID_sha256   SHA256_DIGEST_LENGTH
the private key file is private.pem
the public key file is public.pem
the public key sha256 digest file is pub_digset
the img file is sunxi.dtb
sunxi.dtb rsa sha256 signature file is sig.bin
*/

 
static int get_pem_public_key(const char *key_path, RSA **pub_rsa)
{
	FILE *fp;
	fp = fopen(key_path, "r");
	if(fp == NULL)
	{
		printf("public key path open failed\n");
		return -1;
	}
	//密钥的PEM数据中没有RSA使用下面API，这里申请了内存空间，需要释放
	*pub_rsa = PEM_read_RSA_PUBKEY(fp, NULL, NULL, NULL);
	if(*pub_rsa == NULL)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
	
}

static int get_pem_private_key(const char *key_path, RSA **pri_rsa)
{
	FILE *fp;
	fp = fopen(key_path, "r");
	if(fp == NULL)
	{
		printf("the private key file open failed\n");
		return -1;
	}
	//密钥的PEM数据中有RSA时，使用下面API
	*pri_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
	if(*pri_rsa == NULL)
	{
		fclose(fp);
		return -1;
	}
	fclose(fp);
	return 0;
}

static int get_bio_public_key(BIO *bio, RSA **pub_rsa, char *pub_buf)
{
	BIO_puts(bio, pub_buf);
	*pub_rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
	if(*pub_rsa == NULL)
		return -1;
	return 0;
}

static int get_bio_private_key(BIO *bio, RSA **pri_rsa, char *pri_buf)
{
	BIO_puts(bio, pri_buf);
	*pri_rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
	if(*pri_rsa == NULL)
		return -1;
	return 0;
}

static int file_read(const char *path, char *buf)
{
	int fd, size;
	int total_size = 0;
	char *p = buf;
	fd = open(path, O_RDWR);
	if(fd < 0)
	{
		printf("file open failed\n");
		return -1;
	}
	do
	{
		size = read(fd, p, 100);
		total_size += size;
		p += size;
	}while(size);
	close(fd);
	return total_size;
	
}


int main(void)
{
	char img_buf[100*1024];
	char img_sig_buf[32];
	char img_rsa_sig_buf[512];
	char pem_pub_key_buf[512];
	char pem_pub_key_sig_in_buf[32];
	char pem_pub_key_sig_buf[32];
	char pem_rsa_sig_buf[32];
	int pem_rsa_sig_size;
	int pem_pub_key_size;
	int img_rsa_sig_size;
	int img_size;
	BIO *bio=NULL;
	RSA *public_rsa = NULL;
	RSA *private_rsa = NULL;
	int retval;

	get_pem_private_key("private.pem", &private_rsa);
	get_pem_public_key("public.pem", &public_rsa);
	img_size = file_read("sunxi.dtb", img_buf);
	if(img_size <= 0)
	{
		printf("img file read err\n");
		goto err;
	}
	SHA256(img_buf, img_size, img_sig_buf);
	retval = RSA_sign(NID_sha256, img_sig_buf, SHA256_DIGEST_LENGTH, img_rsa_sig_buf,
		             &img_rsa_sig_size, private_rsa);
	if(retval != 1)
	{
		printf("rsa sign failed\n");
		goto err;
	}
	retval = RSA_verify(NID_sha256, img_sig_buf, SHA256_DIGEST_LENGTH, img_rsa_sig_buf,
		                img_rsa_sig_size, public_rsa);
	if(retval != 1)
	{
		printf("img verify failed\n");
		goto err;
	}
	printf("sign img and verify ok\n");

	pem_pub_key_size = file_read("public.pem", pem_pub_key_buf);
	if(pem_pub_key_size <= 0)
	{
		printf("public.pem file read failed\n");
		goto err;
	}
	SHA256(pem_pub_key_buf, pem_pub_key_size, pem_pub_key_sig_buf);
	if(file_read("pub_digset", pem_pub_key_sig_in_buf) != 32)
	{
		printf("pub_digset file read failed\n");
		goto err;
	}
	if(memcmp(pem_pub_key_sig_in_buf, pem_pub_key_sig_buf, 32))
	{
		printf("public key verify failed\n");
		goto err;
	}
	printf("public key verify ok\n");

	pem_rsa_sig_size = file_read("sig.bin", pem_rsa_sig_buf);
	if(pem_rsa_sig_size <= 0)
	{
		printf("img rsa signature file read failed\n");
		goto err;
	}
	retval = RSA_verify(NID_sha256, img_sig_buf, SHA256_DIGEST_LENGTH, pem_rsa_sig_buf,
		                pem_rsa_sig_size, public_rsa);
	if(retval != 1)
	{
		printf("img sign verify failed\n");
		goto err;
	}
	printf("img sign verify ok\n");

	RSA_free(public_rsa);
    RSA_free(private_rsa);
	return 0;
err:
	RSA_free(public_rsa);
    RSA_free(private_rsa);
	return -1;
}


