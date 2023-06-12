//Includes
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>

//defines
#define TAM_BUFFER_CRIPTO 1024
#define TAM_BUFFER_DECRIPTO 1024
#define TAM_BUFFER_KEY 32 //32 bytes = 256 bits
#define TAM_BUFFER_IV 16 //16 bytes = 128 bits
#define TAM_MAX_MENSAGEM_BOAS_VINDAS 300
#define TAM_MAX_MENSAGEM_CLIENT 2000
#define NUM_MAX_CONEXAO_CLIENTS 1
#define PORTA_SOCKET_SERVER 8888

//IMPORTANTE: como exemplo / aprendizado, o key.txt e iv.txt serão salvos na mesma pasta do programa.
//Porém, "na vida real", os arquivos devem estar em local seguro, o que significa dizer que devem estar em pastas somente acessiveis pelo root
#define CAMINHO_ARQUIVO_KEY "key.txt" //contem o caminho para o arquivo que contem a key (32 bytes)
#define CAMINHO_ARQUIVO_IV "iv.txt" //contem o caminho para o arquivo que contem o iv (16 bytes)

//Variaveis globais
char buffer_key[TAM_BUFFER_KEY];
char buffer_iv[TAM_BUFFER_IV];
unsigned char ciphertext[TAM_BUFFER_CRIPTO];
int decryptedtext_len, ciphertext_len;

//prototypes locais
void carregar_key_e_iv(void);
void error(char* msg);
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

//Funcao: Exibe o erro de socket client na tela e finaliza o programa
//Paramentros: nenhum
//Retorno: nennhum
void error(char* msg) {
    perror(msg);
    exit(0);
}

//Funcao: carrega Key e IV da criptografia
//Paramentros: nenhum
//Retorno: nennhum
void carregar_key_e_iv(void) {
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

//Programa principal
int main(int argc, char* argv[]) {
    int sockfd, portno, n;
    int i;
    struct sockaddr_in serv_addr;
    struct hostent* server;
    char buffer[256];
    unsigned char decryptedtext[TAM_BUFFER_DECRIPTO];
    //Inicializacoes do OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //carrega a key e o iv salvos em local adequado
    carregar_key_e_iv();

    //Criacao do socket client
    portno = PORTA_SOCKET_SERVER;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
        error("\nERRO: impossivel abrir socket nesta porta");

    //Aqui, o socket client e criado.
    //OBS: na funcao gethostbyname(), pode ser passado como
    //parametro tanto um DNS quanto um IP. Como neste teste será usado comunicação entre dois sockets localmente
    //na Raspbnerry Pi, será utiliado o IP de loopbakc (127.0.0.1)
    server = gethostbyname("192.168.1.7");
    printf("\nTentando conectar ao host %s...\n", server->h_name);

    //verifica se houve falha ao contactar o host
    if (server == NULL) {
        fprintf(stderr, "\nERRO: o host informado nao esta ao alcance ou nao existe.\n");
        exit(0);
    }

    //inicializa com zeros a estrutura de socket
    bzero((char*)&serv_addr, sizeof(serv_addr));

    //preenche a estrutura de socket
    serv_addr.sin_family = AF_INET;
    bcopy((char*)server->h_addr_list,
        (char*)&serv_addr.sin_addr.s_addr,
        server->h_length);
    serv_addr.sin_port = htons(portno);

    //Tenta se conectar ao socket server
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
        error("\nERRO: impossivel conectar ao host.");
    else
        printf("\nConexao ao host bem sucedida!\n\n");

    //le a mensagem a ser enviada.
    //OBS: aqui foi usado fgets() pois a funcao gets() possui uma falha,
    //podendo causar buffer overflow.
    printf("Mensagem a ser enviada: ");
    memset(buffer, 0x00, sizeof(buffer));
    fgets(buffer, sizeof(buffer), stdin);

    //Criptografa a mensagem construida e a envia ao host
    ciphertext_len = encrypt(buffer, strlen((char*)buffer), buffer_key, buffer_iv, ciphertext);
    n = write(sockfd, ciphertext, ciphertext_len);

    if (n < 0)
        error("ERRO: impossivel enviar mensagem criptografada ao host");

    bzero(buffer, 256);

    //aguarda receber mensagem criptografada do host
    n = read(sockfd, ciphertext, 255);
    if (n < 0)
        error("ERRO: falha ao receber dados do host");
    //Descriptografa a mensagem e a exibe na tela
    ciphertext_len = n;
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, buffer_key, buffer_iv, decryptedtext);

    printf("\n\n[Mensagem recebida do servidor]\n\n");

    for (i = 0; i < decryptedtext_len; i++)
        printf("%c", decryptedtext[i]);

    printf("\n\n");

    //fim de programa
    return 0;
}