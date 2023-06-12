//includes
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

//defines
#define TAM_BUFFER_CRIPTO 1024
#define TAM_BUFFER_DECRIPTO 1024
#define TAM_BUFFER_KEY 32 //32 bytes = 256 bits
#define TAM_BUFFER_IV 16 //16 bytes = 128 bits
#define TAM_MAX_MENSAGEM_BOAS_VINDAS 300
#define TAM_MAX_MENSAGEM_CLIENT 2000
#define NUM_MAX_CONEXAO_CLIENTS 1
#define PORTA_SOCKET_SERVER 8888 //Nota: o valor da porta pode ser qualquer um entre 2000 e 65535.

//IMPORTANTE: como exemplo / aprendizado, o key.txt e iv.txt serão salvos na mesma pasta do programa.
//Porém, "na vida real", os arquivos devem estar em local seguro, o que significa dizer que devem estar em pastas somente acessiveis pelo root
#define CAMINHO_ARQUIVO_KEY "key.txt" //contem o caminho para o arquivo que contem a key (32 bytes)
#define CAMINHO_ARQUIVO_IV "iv.txt" //contem o caminho para o arquivo que contem o iv (16 bytes)

//Variaveis globais
char buffer_key[TAM_BUFFER_KEY];
char buffer_iv[TAM_BUFFER_IV];
unsigned char ciphertext[TAM_BUFFER_CRIPTO]; //Buffer para o dado criptografado. Declare-o com um tamanho grande, para n$
int decryptedtext_len, ciphertext_len;

//prototypes locais
void carrega_key_e_iv(void);
void handle_errors(void);
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext);
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext);

//Funcao: handle_errors - usada quando ocorre erro na encritptacao ou decriptacao, servindo para colocar na tela o erro acusado pelo OpenSSL
//Parametros: nenhum
//Retorno: nenhum
void handle_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

//Funcao: encrypt - faz a encriptacao de uma mensagem de texto (usando OpenSSL, em AES 256 CBC)
//Parametros:
// - Ponteiro para mensagem de texto a ser criptografada
// - Tamanho da mensagem de texto a ser criptografada
// - Ponteiro para a key
// - Ponteiro para a iv
// - Ponteiro para a variavel que ira conter o dado criptografado / resultado da criptografia
//Retorno: tamanho do dado criptografado
int encrypt(unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx; //objeto de context utilizado na encriptacao. Por razões de seguranca, deve ser limpo ao final do processo.
    int len; //Guarda o tamanho da mensagem criptografada durante o processo
    int ciphertext_len; //Contem o tamanho final da mensagem criptografada

    //Cria/inicializa contexto
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();

    /* Inicializa a operacao de encriptacao
    IMPORTANTE
    - Como o algoritmo de criptografia usado e o AES 256 CBC, tenha certeza que
    a key e o iv tem o tamanho correto / esperado. Neste caso, significa dizer que
    a key deve ter 32 bytes (=256 bits) e o iv deve ter 16 bytes (=128 bits)

    Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();

    // Aqui, a mensagem de texto e efetivamente encriptada.
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handle_errors();

    ciphertext_len = len;

    //Finalizacao da encriptacao. No processo de finalizacao de encriptacao e feito o padding.
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handle_errors();
    ciphertext_len += len;

    //Limpa o objeto de contexto
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//Funcao: decrypt - faz a decriptacao de uma mensagem de texto (usando OpenSSL,$
//Parametros:
// - Ponteiro a mensagem criptografada
// - Tamanho da mensagem criptografada
// - Ponteiro para a key
// - Ponteiro para a iv
// - Ponteiro para a variavel que ira conter o dado decriptografado / resultado $
//Retorno: tamanho do dado decriptografado
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx; //objeto context utilizado na decriptografia. Por razoes de seguranca, ele deve ser limpo ao final do processo
    int len; //tamanho do dado decriptografado ao longo do processo.
    int plaintext_len; //tamanho final do dado decriptografado

    //Cria / inicializa o context
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handle_errors();

    /* Inicializa a operacao de decriptacao
    IMPORTANTE
    - Como o algoritmo de criptografia usado e o AES 256 CBC, tenha certeza que
    a key e o iv tem o tamanho correto / esperado. Neste caso, significa dizer $
    a key deve ter 32 bytes (=256 bits) e o iv deve ter 16 bytes (=128 bits)

    Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handle_errors();

    //Aqui ocorre a decriptacao de fato.
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();

    plaintext_len = len;

    //Finalizacao da decriptacao.
    //Em caso de erro, mostra o erro acusado pelo OpenSSL na tela.
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handle_errors();
    plaintext_len += len;

    //Limpa objeto de context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

//Funcao: carrega Key e IV da criptografia
//Paramentros: nenhum
//Retorno: nennhum
void carrega_key_e_iv(void) {
    FILE* arq;
    char* ptKey;
    char* ptIV;
    int contador_bytes;

    //carrega a key (32 bytes = 256 bits)
    arq = fopen(CAMINHO_ARQUIVO_KEY, "r");
    if (arq == NULL)
        printf("Erro: impossivel carregar a KEY\n");
    else {
        contador_bytes = 0;
        ptKey = &buffer_key[0];
        while (contador_bytes < TAM_BUFFER_KEY) {
            *ptKey = fgetc(arq);
            ptKey++;
            contador_bytes++;
        }
    }
    fclose(arq);
    printf("[KEY] Carregada com sucesso.\n\n");

    //Carrega o IV (16 bytes = 128 bits)
    arq = fopen(CAMINHO_ARQUIVO_IV, "r");
    if (arq == NULL)
        printf("Erro: impossivel carregar o IV\n");
    else {
        contador_bytes = 0;
        ptIV = &buffer_iv[0];
        while (contador_bytes < TAM_BUFFER_IV) {
            *ptIV = fgetc(arq);
            ptIV++;
            contador_bytes++;
        }
    }
    fclose(arq);
    printf("[IV] Carregado com sucesso.\n\n");
}

int main(int argc, char* argv[]) {
    int socket_desc, client_sock, c, read_size; //socket_desc: descriptor do socket servidor
    //client_sock: descriptor da conexao com o client
    //read_size: contem o tamanho da estrutura que contem os dados do socket
    struct sockaddr_in server, client; //server: estrutura com informações do socket (lado do servidor)
    //client: estrutura com informações do socket (lado do client)
    char client_message[TAM_MAX_MENSAGEM_CLIENT]; //array utilizado como buffer dos bytes enviados pelo client
    char msg_boas_vindas[TAM_MAX_MENSAGEM_BOAS_VINDAS]; //array que contem a mensagem de boas vindas (enviada no momento que a conexao e estabelecida)
    char msg_client[TAM_MAX_MENSAGEM_CLIENT]; //array que contem mensagem enviada ao client enquanto a conexao estiver estabelecida

    //Buffer para mensagem decriptada
    unsigned char decryptedtext[TAM_BUFFER_DECRIPTO];
    int i;

    //Inicializacoes do OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //carrega a key e o iv salvos em local adequado
    carrega_key_e_iv();

    //Tenta criar socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        perror("Impossivel criar socket");
        return 1;
    }
    puts("Socket criado com sucesso!");

    //Prepara a estrutura de socket do servidor (contendo configurações do socket, como protocolo IPv4, porta de comunicacao e filtro de ips que podem se conectar)
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORTA_SOCKET_SERVER);

    //Tenta fazer Bind (informa que o referido socket operara na porta definida por PORTA_SOCKET_SERVER)
    if (bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("Erro ao fazer bind");
        return 1;
    }
    puts("Bind feito com sucesso!");

    //Faz o Listen. É permitido apenas uma conexao no socket
    listen(socket_desc, NUM_MAX_CONEXAO_CLIENTS);

    //Aguarda uma conexao
    puts("Aguardando conexao...");
    c = sizeof(struct sockaddr_in);

    client_sock = accept(socket_desc, (struct sockaddr*)&client, (socklen_t*)&c);
    //foi recebido um pedido de conexao. Verifica se o pedido foi bem sucedido
    if (client_sock < 0) {
        perror("Falha ao aceitar conexao");
        return 1;
    }
    puts("Conexao aceita!");

    //Aguarda receber bytes do client
    while ((read_size = recv(client_sock, client_message, 2000, 0)) > 0) {

        //Descriptografa a mensagem
        ciphertext_len = read_size;
        memcpy(ciphertext, client_message, read_size);
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, buffer_key, buffer_iv, decryptedtext);

        //Mostra a mensagem recebida (decriptografada) na tela:
        printf("\n\nMensagem decriptografada: %s\n\n", decryptedtext);

        //Constroi a mensagem descriptografada a ser enviada de volta ao client
        memset(msg_client, 0, TAM_MAX_MENSAGEM_CLIENT);
        memcpy(msg_client, decryptedtext, strlen(decryptedtext));
        sprintf(msg_client, "%s - modificado", msg_client);
        printf("\n\nMensagem a ser enviada de volta ao client: %s.\n\n", msg_client);

        //Criptografa a mensagem construida e a envia ao client
        ciphertext_len = encrypt(msg_client, strlen((char*)msg_client), buffer_key, buffer_iv, ciphertext);

        write(client_sock, ciphertext, ciphertext_len);
        memset(msg_client, 0, TAM_MAX_MENSAGEM_CLIENT);
        memset(client_message, 0, TAM_MAX_MENSAGEM_CLIENT);
    }

    //client se desconectou. O programa sera encerrado.
    if (read_size == 0) {
        puts("Client desconectado. A aplicacao sera encerrada.");
        fflush(stdout);
        close(client_sock); //fecha o socket utilizado, disponibilizando a porta para outras aplicacoes
    }
    else if (read_size == -1) //caso haja falha na recepção, o programa sera encerrado
        perror("recv failed");

    return 0;
}