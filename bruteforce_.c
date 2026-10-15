#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <rpc/des_crypt.h>

// Descifra el texto usando una clave DES.
void decrypt(long key, char *ciph, int len){
  long k = 0;

  // Ajusta la clave al formato utilizado por DES.
  for(int i=0; i<8; ++i){
    key <<= 1;
    k += (key & (0xFE << i*8));
  }
  des_setparity((char *)&k);
  ecb_crypt((char *)&k, (char *) ciph, 16, DES_DECRYPT);
}


// Cifra el texto usando una clave DES.
void encrypt(long key, char *ciph){
  long k = 0;

  // Ajusta la clave al formato utilizado por DES.
  for(int i=0; i<8; ++i){
    key <<= 1;
    k += (key & (0xFE << i*8));
  }
  des_setparity((char *)&k); 
  ecb_crypt((char *)&k, (char *) ciph, 16, DES_ENCRYPT);
}


// Prueba una clave y busca una frase conocida en el texto descifrado.
char search[] = "Un archivo";
int tryKey(long key, char *ciph, int len){
  char temp[len+1]; 
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, len);
  return strstr((char *)temp, search) != NULL;
}

// Texto original utilizado para la prueba.
char eltexto[] = "Un archivo digital permite conservar la memoria de una comunidad y compartir sus historias de forma organizada.";
long the_key = 18014398509481984;


int main(int argc, char *argv[]){ 
  int N, id;
  long upper = (1L <<56); //upper bound DES keys 2^56
  long mylower, myupper;
  MPI_Status st;
  MPI_Request req;

  // Prepara una copia del texto y la cifra antes de iniciar la búsqueda.
  int ciphlen = strlen(eltexto);
  MPI_Comm comm = MPI_COMM_WORLD;

  char cipher[ciphlen+1];
  memcpy(cipher, eltexto, ciphlen);
  cipher[ciphlen]=0;
  encrypt(the_key, cipher);

  // Inicia MPI y obtiene el total de procesos y el identificador actual.
  MPI_Init(NULL, NULL);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  long found = 0;
  int ready = 0;

  // Divide el espacio de claves entre los procesos disponibles.
  long range_per_node = upper / N;
  mylower = range_per_node * id;
  myupper = range_per_node * (id+1) -1;
  if(id == N-1){
    myupper = upper;
  }
  printf("Process %d lower %ld upper %ld\n", id, mylower, myupper);

  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

  // Prueba las claves asignadas hasta encontrar la correcta.
  for(long i = mylower; i<myupper; ++i){
    MPI_Test(&req, &ready, MPI_STATUS_IGNORE);
    if(ready)
      break;  

    if(tryKey(i, cipher, ciphlen)){
      found = i;
      printf("Process %d found the key\n", id);

      // Notifica la clave encontrada a todos los procesos.
      for(int node=0; node<N; node++){
        MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
      }
      break;
    }
  }

  if(id==0){
    // El proceso principal muestra la clave y el texto descifrado.
    MPI_Wait(&req, &st);
    decrypt(found, cipher, ciphlen);
    printf("Key = %li\n\n", found);
    printf("%s\n", cipher);
  }

  MPI_Finalize();
}
