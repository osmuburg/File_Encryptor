#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "sha256.h"
#include "aes.h"

bool dflag = false; //bandera encriptación/desencriptación

void print_help(char *command)
{
	printf("secret encripta o desincripta un archivo usando el algoritmo AES.\n");
	printf("uso:\n %s [-d] -k <key> <nombre_archivo>\n", command);
	printf(" %s -h\n", command);
	printf("Opciones:\n");
	printf(" -h\t\t\tAyuda, muestra este mensaje\n");
	printf(" -d\t\t\tDesincripta el archivo en lugar de encriptarlo.\n");
	printf(" -k <key>\t\tEspecifica la clave (key) de encriptación, 128-bits (16 bytes) en hex.\n");
}

int generarclave_sha256(char *frase, BYTE *clave, int n_bits) {
	BYTE hash[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (BYTE*)frase, strlen(frase));
	sha256_final(&ctx, hash);
	// Truncar el hash a n_bits (n_bits/8 bytes)

	memcpy(clave, hash, n_bits / 8);
	return 0;
}
int main(int argc, char **argv)
{
    struct stat mi_stat;
    char *input_file = NULL;
    char *key_arg_str = NULL;
    long original_size;  // Declara original_size aquí
    int fd_read, fd_write;  // Declara fd_read y fd_write aquí

    int opt, index;

    while ((opt = getopt (argc, argv, "dhk:")) != -1) {
        switch(opt) {
            case 'd':
                dflag = true;
                break;
            case 'h':
                print_help(argv[0]);
                return 0;
            case 'k':
                key_arg_str = optarg;
                break;
            case '?':
            default:
                fprintf(stderr, "uso: %s [-d] -k <key> <nombre_archivo>\n", argv[0]);
                fprintf(stderr, "     %s -h\n", argv[0]);
                return 1;
        }
    }

    // Aquí recoge argumentos que no son opción, por ejemplo, el nombre del input file
    for (index = optind; index < argc; index++)
        input_file = argv[index];

    if (!input_file) {
        fprintf(stderr, "Especifique el nombre del archivo.\n");
        fprintf(stderr, "uso: %s [-d] -k <key> <nombre_archivo>\n", argv[0]);
        fprintf(stderr, "     %s -h\n", argv[0]);
        return 1;
    } else {
        // Verificar existencia y tamaño de un archivo
        if (stat(input_file, &mi_stat) < 0) {
            fprintf(stderr, "Archivo %s no existe!\n", input_file);
            return 1;
        } else {
            printf("Leyendo el archivo %s (%ld bytes)...\n", input_file, mi_stat.st_size);
        }
    }

    // Arreglo bytes clave de encriptación/desencriptación
    BYTE key_arg_binario[16];
    WORD key_schedule[60];

    // Buffer de encriptación/desencriptación
    BYTE aes_buffer[AES_BLOCK_SIZE];
    // Buffer de lectura, inicializado en cero
    BYTE read_buffer[AES_BLOCK_SIZE] = {0};

    // Valida la clave de encriptación
    if (key_arg_str) {
        generarclave_sha256(key_arg_str, key_arg_binario, 128);
    } else {
        fprintf(stderr, "Error al especificar la clave de encriptación.\n");
        fprintf(stderr, "uso: %s [-d] -k <key> <nombre_archivo>\n", argv[0]);
        fprintf(stderr, "     %s -h\n", argv[0]);
        return 1;
    }

    aes_key_setup(key_arg_binario, key_schedule, 128);

    // Abrir archivo solo lectura
    fd_read = open(input_file, O_RDONLY, 0);

    // Crear nombre archivo de salida
    char *output_file = (char *) calloc(strlen(input_file) + 5, 1);
    strcpy(output_file, input_file);

    if (dflag) {
        strcat(output_file, ".dec");
        // Leer el tamaño original del archivo
        read(fd_read, &original_size, sizeof(long));
    } else {
        strcat(output_file, ".enc");
    }

    // Crear/truncar archivo de salida con permisos de escritura y lectura para el dueño
    fd_write = open(output_file, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);

    if (!dflag) {
        // Encriptación: escribir el tamaño del archivo original en los primeros 8 bytes
        original_size = mi_stat.st_size;
        write(fd_write, &original_size, sizeof(long));
    }

    // Leer el archivo de lectura 16 bytes a la vez
    int bytes_leidos;
    while ((bytes_leidos = read(fd_read, read_buffer, AES_BLOCK_SIZE)) > 0) {
        if (dflag)
            aes_decrypt(read_buffer, aes_buffer, key_schedule, 128);
        else
            aes_encrypt(read_buffer, aes_buffer, key_schedule, 128);

        write(fd_write, aes_buffer, AES_BLOCK_SIZE);

        // Encerar buffer
        memset(read_buffer, 0, sizeof read_buffer);
    }

    if (dflag) {
        // Truncar el archivo desencriptado al tamaño original
        ftruncate(fd_write, original_size);
        printf("Archivo %s desencriptado exitosamente en %s...\n", input_file, output_file);
    } else {
        printf("Archivo %s encriptado exitosamente en %s...\n", input_file, output_file);
    }

    free(output_file);
    close(fd_read);
    close(fd_write);

    return 0;
}
