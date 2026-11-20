# CLI `sers`

O CLI retorna JSON em stdout e mensagens de erro em stderr. Os comandos disponíveis são:

```text
sers --version
sers backend detect
sers inspect <arquivo.sers> [--publisher-key <chave-publica-hex-minuscula>]
sers package build <config.json> <saida.sers>
sers identity init <arquivo-de-chave>
sers identity show <arquivo-de-chave>
sers identity registration-request <arquivo-de-chave> --application <id>
```

## Construir um pacote

Crie um JSON com os metadados do pacote, os caminhos dos segredos e os módulos. Os caminhos relativos são
resolvidos a partir do diretório do JSON. `created_at` é opcional e, quando ausente, usa o relógio do sistema em
segundos Unix.

```json
{
  "application_id": "acme.editor",
  "version": "1.2.3",
  "version_counter": 7,
  "execution_policy": "software_allowed",
  "created_at": 1795179109,
  "signing_seed_file": "secrets/publisher.seed",
  "package_key_file": "secrets/package.key",
  "modules": [
    { "module_id": "core", "abi_version": 1, "file": "modules/core.bin" }
  ]
}
```

`signing_seed_file` contém exatamente 32 bytes de seed Ed25519; `package_key_file` contém exatamente 32 bytes de
chave AES-256. Ambos são lidos como bytes crus, não como texto hexadecimal. O SERS não gera nem protege esses
arquivos. Restrinja o acesso deles com o sistema operacional ou forneça-os por um gerenciador de segredos. Use
uma chave de pacote independente por pacote e cadastre-a no Key Broker correspondente. Não coloque segredos no
JSON, em argumentos do processo, no controle de versão ou em logs.

`execution_policy` aceita `software_allowed`, `hardware_required` ou `remote_execution_required`. A política não
cria o backend correspondente: `hardware_required` continua falhando de forma fechada e execução remota ainda
não existe.

O parser rejeita campos JSON desconhecidos, limita o JSON a 1 MiB, limita cada módulo ao máximo do formato, o
total de texto simples a 256 MiB e a quantidade de módulos a 256. O CLI verifica a assinatura e a integridade do
pacote construído antes de gravá-lo. Ele não substitui arquivos existentes; uma falha de escrita ou encerramento
forçado durante a gravação pode deixar uma saída parcial, que deve ser removida antes de tentar novamente.

Exemplo:

```sh
cargo run -p sers-cli -- package build build.json dist/editor.sers
```

A resposta inclui o identificador e a chave pública do publicador, tamanho e caminho da saída. A chave pública
deve ser distribuída por um canal confiável e instalada no trust store do consumidor; o identificador sozinho
não estabelece confiança.

## Inspecionar

Sem uma chave confiável, `inspect` mostra somente metadados do contêiner, marcados como não verificados. Com
`--publisher-key`, verifica assinatura e integridade antes de interpretar/exibir o manifesto. A chave deve ser
hexadecimal minúscula canônica de 32 bytes:

```sh
cargo run -p sers-cli -- inspect dist/editor.sers --publisher-key CHAVE_PUBLICA_HEX
```

## Identidade de instalação

```sh
cargo run -p sers-cli -- identity init ~/.config/sers/installation.key
cargo run -p sers-cli -- identity show ~/.config/sers/installation.key
cargo run -p sers-cli -- identity registration-request ~/.config/sers/installation.key --application acme.editor
```

No Unix, `identity init` cria ou carrega uma chave Ed25519 em arquivo `0600`; os comandos retornam somente o id
da instalação, a chave pública e, no último comando, a prova de posse assinada. No Windows, a keystore ainda não
está implementada e os comandos falham fechados. O arquivo Unix protege contra outros usuários locais sem
privilégio, não contra processos executados pelo mesmo usuário, root ou depuração. O pedido gerado não registra
a instalação na rede: o gateway não existe e o protocolo ainda exige que o cliente envie também a credencial da
licença pelo canal apropriado.

## Limites atuais

Não há ainda comandos para registrar instalações, pacotes ou licenças na rede, nem conectar ao Control Plane. No
Windows, o armazenamento de chave de instalação permanece indisponível. A construção de pacotes aceita arquivos
de chaves já provisionados, mas não substitui um KMS/HSM nem um fluxo de assinatura protegido.
