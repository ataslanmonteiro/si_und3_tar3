// Importar os módulos necessários
const { generateKeyPairSync, createSign, createVerify } = require('crypto');

// Passo 1: Gerar Chaves Pública e Privada
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048, // Tamanho da chave em bits
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem' // Formato PEM (Privacy Enhanced Mail)
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// Passo 2: Função para Assinar o Texto
function assinarTexto(texto, chavePrivada) {
    const assinador = createSign('rsa-sha256'); // Algoritmo de assinatura
    assinador.update(texto);
    const assinatura = assinador.sign(chavePrivada, 'hex'); // Assina e retorna em hexadecimal
    return assinatura;
}

// Passo 3: Função para Verificar a Assinatura
function verificarAssinatura(texto, assinatura, chavePublica) {
    const verificador = createVerify('rsa-sha256');
    verificador.update(texto);
    const ehValido = verificador.verify(chavePublica, assinatura, 'hex');
    return ehValido;
}

// Passo 4: Simular o Uso
const textoOriginal = "Este é um texto para ser assinado digitalmente.";
const assinatura = assinarTexto(textoOriginal, privateKey);

console.log("Texto Original:", textoOriginal);
console.log("Assinatura:", assinatura);

// Verificar a assinatura
const textoCorretoVerificado = verificarAssinatura(textoOriginal, assinatura, publicKey);
console.log("Verificação do texto original:", textoCorretoVerificado); // Deve ser true

// Passo 5: Simular Alteração do Texto
const textoAlterado = "Este é um texto ALTERADO para ser assinado digitalmente.";
const textoAlteradoVerificado = verificarAssinatura(textoAlterado, assinatura, publicKey);
console.log("Verificação do texto alterado:", textoAlteradoVerificado); // Deve ser false