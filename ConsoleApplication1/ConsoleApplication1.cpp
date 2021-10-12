#include <iostream>
#include <sodium.h>
#include <stdio.h>

#pragma warning(disable : 4996)

#define CHUNK_SIZE 10240

static int sign(const char* file) {
	unsigned char pk[crypto_sign_PUBLICKEYBYTES]; 
	unsigned char sk[crypto_sign_SECRETKEYBYTES]; 
	unsigned char  buf_in[CHUNK_SIZE];

	crypto_sign_keypair(pk, sk); 
	crypto_sign_state state; 
	unsigned char sig[crypto_sign_BYTES];

	FILE* fp;
	size_t         rlen;
	int            eof;

	fp = fopen(file, "rb");
	if (fp == 0) {
		std::cout << "fallo en abrir el archivo";
		return 1;
	}

	crypto_sign_init(&state); 
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp);
		eof = feof(fp);
		crypto_sign_update(&state, buf_in, rlen);
	} while (!eof);
	//std::cout << buf_in;
	crypto_sign_final_create(&state, sig, NULL, sk);
	fclose(fp);

	fp = fopen(file, "rb");
	if (fp == 0) {
		std::cout << "fallo en abrir el archivo";
		return 1;
	}
	crypto_sign_init(&state);
	do {
		rlen = fread(buf_in, 1, sizeof buf_in, fp);
		eof = feof(fp);
		//std::cout << eof;
		crypto_sign_update(&state, buf_in, rlen);
	} while (!eof);

	if (crypto_sign_final_verify(&state, sig, pk) != 0) {    
		/* message forged! */
		std::cout << "algo salio mal?\n";
		fclose(fp);
		return 1;
	}
	//std::cout << "todo bien\n";
	fclose(fp);
	return 0;
}

static int encrypt(
	const char* target_file, const char* source_file,
	const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
		unsigned char  buf_in[CHUNK_SIZE];   
		unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];   
		unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

		crypto_secretstream_xchacha20poly1305_state st;

		FILE* fp_t, * fp_s;
		unsigned long long out_len;
		size_t         rlen;
		int            eof;
		unsigned char  tag;

		//errno_t err;
		//err = fopen_s(&fp_t, "C:\\Documents encrypted.txt", "r");
		fp_s = fopen(source_file, "rb");
		if (fp_s == 0) {
			std::cout << "fallo en abrir el archivo source";
			return 1;
		}
		fp_t = fopen(target_file, "wb");
		if (fp_t == 0) {
			std::cout << "fallo en abrir el archivo target";
			return 1;
		}
	
		crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);    
		fwrite(header, 1, sizeof header, fp_t); 
		
		do {    
			rlen = fread(buf_in, 1, sizeof buf_in, fp_s);        
			eof = feof(fp_s); 
			tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;  
			//std::cout << eof;
			crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,                                                   
				NULL, 0, tag);        
			fwrite(buf_out, 1, (size_t) out_len, fp_t);    
		} while (! eof); 
		
		fclose(fp_t);    
		fclose(fp_s);  

		//std::cout << "hizo algo aqui al final?";
		return 0;
}

 static int decrypt(
	const char *target_file, const char *source_file,        
	const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]){    
		unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];    
		unsigned char  buf_out[CHUNK_SIZE];    
		unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];    
		crypto_secretstream_xchacha20poly1305_state st;    
		FILE          *fp_t, *fp_s;    
		unsigned long long out_len;    
		size_t         rlen;    
		int            eof;    
		int            ret = -1;    
		unsigned char  tag;    
		fp_s = fopen(source_file, "rb");    
		fp_t = fopen(target_file, "wb");    
		fread(header, 1, sizeof header, fp_s);    
		if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {        
			goto ret; //incomplete header    
		} do {        
			rlen = fread(buf_in, 1, sizeof buf_in, fp_s);        
			eof = feof(fp_s);        
			if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {            
				goto ret; //corrupted chunk        
			} if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {            
				goto ret; // premature end (end of file reached before the end of the stream)        
			} fwrite(buf_out, 1, (size_t) out_len, fp_t);    
		} while (! eof);    
		ret = 0;ret:    
		fclose(fp_t);    
		fclose(fp_s);    
		return ret;
}

int main(void){  
	unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	if (sodium_init() != 0) {
		return 1;    
	} 
	//std::cout << "sodium inicia bien";
	
	std::cout << sign("C:\\Users\\macie\\Documents\\test1.txt");
	std::cout << "\nSe firmo un archivo de 1MB\n";
	
	int opt;
	std::cout << "Seleccionar archivo a cifrar: 0 = 1MB, 1 = 10MB\n";
	std::cin >> opt;

	crypto_secretstream_xchacha20poly1305_keygen(key);

	if (opt == 0) {
		if (encrypt("C:\\Users\\macie\\Documents\\encrypted.txt", "C:\\Users\\macie\\Documents\\test1.txt", key) != 0) {
			std::cout << "encriptar falla?";
			return 1;
		}
		//std::cout << "encriptar funciona?";
		if (decrypt("C:\\Users\\macie\\Documents\\decrypted.txt", "C:\\Users\\macie\\Documents\\encrypted.txt", key) != 0) {
			return 1;
		}
	}
	else {
		if (encrypt("C:\\Users\\macie\\Documents\\encrypted.txt", "C:\\Users\\macie\\Documents\\test10.txt", key) != 0) {
			std::cout << "encriptar falla?";
			return 1;
		}
		//std::cout << "encriptar funciona?";
		if (decrypt("C:\\Users\\macie\\Documents\\decrypted.txt", "C:\\Users\\macie\\Documents\\encrypted.txt", key) != 0) {
			return 1;
		}
	}
	
	return 0;
}
