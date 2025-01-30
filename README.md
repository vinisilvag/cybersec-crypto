# cybersec-crypto

TP2 da disciplina de Cibersegurança. Implementação de dois métodos de ccriptografia diferentes: CBC e CTR.

## Requisitos

Antes de executar o script `main.py`, certifique-se de que seu ambiente Python possui os seguintes requisitos:

* Python 3.12+ instalado
* Virtualenv instalado
* PyCryptodome instalado (essa biblioteca foi utilizada no lugar do PyCrypto por ser um _fork_ melhor mantido e que não apresenta bugs na hora da instalação, igual o PyCrypto apresentou)

Para instalar as dependências, utilize os comandos:

```bash
# Instalar o Virtualenv
pip3 install virtualenv 
# Criar o ambiente virtual
# Para o desenvolvimento, foi utilizado o comando: python3.12 -m venv env
python<version> -m venv <virtual-environment-name>
# Ativar o ambiente criado
source env/bin/activate
# Instalar o PyCryptodome
pip3 install -r requirements.txt
```

## Uso

O script `main.py` requer argumentos específicos para sua execução:

```bash
python main.py <method> <strategy> <key> <data>
```

### Argumentos

* `<method>`: Define a operação a ser realizada.
  * `encrypt`: Para criptografar os dados.
  * `decrypt`: Para descriptografar os dados.
* `<strategy>`: Define o modo de operação do algoritmo de criptografia.
  * `cbc`: Modo Cipher Block Chaining.
  * `ctr`: Modo Counter.
* `<key>`: A chave utilizada para criptografar ou descriptografar.
* `<data>`:
  * Se method for `encrypt`, este argumento representa o `plaintext` (texto a ser criptografado).
  * Se method for `decrypt`, este argumento representa o `ciphertext` (texto cifrado a ser descriptografado).

## Resultado das questões

A seguir serão listados os resultados para o processo de descriptografar as questões a seguir usando
o método, a chave e a cifra fornecida:

### Questão 1
Chave CBC: 140b41b22a29beb4061bda66b6747e14

Cifra CBC 1: 4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81

**Resposta**: Basic CBC mode encryption needs padding.

### Questão 2
Chave CBC: 140b41b22a29beb4061bda66b6747e14

Cifra CBC 2: 5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253

**Resposta**: Our implementation uses rand. IV

### Questão 3
Chave CTR: 36f18357be4dbd77f050515c73fcf9f2

Cifra CTR 1: 69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329

**Resposta**: CTR mode lets you build a stream cipher from a block cipher.

### Questão 4
Chave CTR: 36f18357be4dbd77f050515c73fcf9f2

Cifra CTR 2: 770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451

**Resposta**: Always avoid the two time pad!


