# Tarea de encriptador de archivos
La tarea consiste en crear un programa de encriptación y desencriptación de archivos usando los algoritmos AES o BLOWFISH y claves con 128, 192 o 256 bits. El programa debe llamarse encrypter y tener el siguiente comportamiento:

```
$ ./encrypter -h
encrypter encripta o desencripta un archivo usando los algoritmos AES o BLOWFISH.
uso:
 ./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>
 ./encrypter -h
Opciones:
 -h			        Ayuda, muestra este mensaje
 -d			        Desencripta el archivo en lugar de encriptarlo.
 -k <passphrase>	Especifica la frase de encriptación.
 -a <algo>		Especifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]
 -b <bits>		Especifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]
```

La clave de encriptación/desencriptación es un hash SHA256 de la frase de encriptación obtenida con la opción -k. Se debe usar 128 bits para encriptar, para esto se debe truncar el hash a partir del byte menos significativo. Usar los archivos *sha256.c* y *sha256.h* en este repositorios para implementar el hash 256.

Además, el archivo encriptado debe contener el tamaño del archivo original en los primeros 8 bytes en formato entero long *little endian*. El archivo desencriptado debe ser idéntico al archivo original (excepto por el nombre).

## Ejemplos de uso

Si deseamos encriptar el archivo documento.txt con la frase de encriptación mifrasesecreta usando BLOWFISH con 256 bits :
```
$ ./encrypter -a blowfish -b 256 -k mifrasesecreta documento.txt 
Usando blowfish con clave de 256 bits...
Archivo documento.txt encriptado exitosamente en documento.txt.enc...
```
Podemos también encriptar con frases largas y si no se usan las opciones -a y/o -b encrypter debe usar valores por defecto:
```
$ ./encrypter -k "mi super frase secreta" documento.txt
Usando aes con clave de 128 bits...
Archivo documento.txt encriptado exitosamente en documento.txt.enc...
```
Si deseamos desencriptar un archivo ya encriptado, por ejemplo documento.txt.enc :
```
$ ./encrypter -d -k mifrasesecreta documento.txt.enc
Usando blowfish con clave de 256 bits...
Archivo documento.txt.enc desencriptado exitosamente en documento.txt...
```
No es necesario especificar el algoritmo ni el número de bits al desencriptar porque encrypter inserta una cabeceara con metadata en los primeros bytes del archivo encriptado.

## Ejemplos de validaciones

Error al especificar el algoritmo:
```
$ ./encrypter -a arcfour -b 128 -k hello image.tar.gz
Algoritmo de encriptación no soportado: arcfour
Algoritmos soportados: aes, blowfish
```
Error al especificar el número de bits de encriptación:
```
$ ./encrypter -a aes -b 150 -k hello image.tar.gz 
Número de bits de encriptación no soportado: 150
Usar: 128, 192 o 256
```
Archivo a desencriptar no tiene extensión .enc :
```
$ ./encrypter -d -k hello image.tar.gz 
Nombre de archivo no valido: archivo sin extensión .enc
```

Uso incorrecto de opciones:
```
$ ./encrypter -z -k hello image.tar.gz.enc
./encrypter: invalid option -- 'z'
uso:
 ./encrypter [-d] [-a <algo>] [-b <bits>] -k <passphrase> <nombre_archivo>
 ./encrypter -h
```

Además debe mostrar mensajes de error si el archivo a leer no existe o tiene el formato de cabecera incorrecto.

## Metadata en archivo .enc

El archivo encriptado debe contener una cabecera con metadata en sus primeros bytes para que encrypter lo pueda desencriptar:
- Tamaño del archivo original en bytes. Tipo long (8 bytes) en Little Endian.
- Máscara de bits (1 byte) con información del algoritmo de encriptación usado y el número de bits de la clave de encriptación.

La cabecera debe por lo tanto tener este formato:
```
   LSB                                              MSB                                                         
 +------+------+------+------+------+------+------+------+------+-----------------                              
 |byte 0|byte 1|byte 2|byte 3|byte 4|byte 5|byte 6|byte 7| mask | Encrypted file                                
 +------+------+------+------+------+------+------+------+------+-----------------                              
 <----------------------File size------------------------>      
```
El byte de la máscara (mask) debe tener el siguiente formato interno:
```
+-------+-------+-------+-------+-------+-------+-------+-------+
|       |       |       |       |       |       |       |       |
| bit 7 | bit 6 | bit 5 | bit 4 | bit 3 | bit 2 | bit 1 | bit 0 |
|       |       |       |       |       |       |       |       |
+-------+-------+-------+-------+-------+-------+-------+-------+
                   BF     AES             256     192     128    
```
Por ejemplo, el uso de este formato de máscara se podría implementar definiendo las siguientes constantes:
```
#define AES       0x10
#define BLOWFISH  0x20
#define KEY_128   0x01
#define KEY_192   0x02
#define KEY_256   0x04
```
y para crear una máscara que por ejemplo defina encriptación con AES usando 256 bits:
```
unsigned char mask = AES | KEY_256;
```

## Compilación
Para compilar el programa:
```
$ make
```
Para compilar facilitando la depuración con gdb:
```
$ make debug
```
Para compilar habilitando la herramienta AddressSanitizer, facilita la depuración en tiempo de ejecución:
```
$ make sanitize
```
