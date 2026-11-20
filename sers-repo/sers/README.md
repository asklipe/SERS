<div align="center">

# SERS

### Security Engineer Reverse System

Pacotes `.sers` assinados e criptografados, autorização por desafio e resposta, e liberação de chaves controlada pela empresa.

</div>

Protótipo 0.1. O SERS é uma infraestrutura em Rust para distribuir as partes sensíveis de uma aplicação em pacotes `.sers` e liberar a chave de cada pacote somente depois de uma autorização verificada por um Control Plane que a empresa controla.

O que é código do SERS: o formato do pacote e sua verificação, o protocolo de desafio e resposta, a política de execução, o Key Broker, a revogação e a auditoria. O que é infraestrutura convencional: Ed25519, X25519, HKDF e AES-256-GCM (crates RustCrypto e dalek), JSON e, nas próximas etapas, TLS e PostgreSQL.

> **Leia antes de usar.** Este código foi escrito sem compilador disponível e **nunca foi compilado nem executado**. Ele não passou por auditoria de segurança. O SERS não promete que a engenharia reversa seja impossível: uma máquina autorizada a executar um pacote recebe a chave e o módulo decifrado, e quem tem acesso total a ela pode inspecioná-los. Detalhes em [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md).

## Rodar a prova do fluxo de autorização

Requer Rust estável recente (Cargo 1.74 ou superior). Não há binário `sers` ainda; a prova é o exemplo e os testes.

```sh
cargo test --workspace
cargo run -p sers-controlplane --example protected_flow
```

O exemplo roda tudo em um único processo, sem rede, e executa estes passos:

1. O publicador cria um pacote `.sers` com um módulo cifrado e confirma que o texto do módulo não aparece no arquivo.
2. Uma instalação registra a própria chave com prova de posse e uma licença.
3. O Control Plane emite um desafio; a instalação o assina; o Control Plane verifica e decide.
4. A chave do pacote chega selada para aquela sessão e o módulo é decifrado.
5. A instalação é revogada e a nova autorização é recusada.
6. Uma aplicação com política `hardware_required` é recusada, porque nenhum TEE é suportado (falha fechada).
7. A trilha de auditoria é conferida.

Os testes em [`control-plane/core/tests/flow.rs`](control-plane/core/tests/flow.rs) cobrem os mesmos fluxos e os casos negativos: replay, desafio expirado, assinatura de outra chave, licença suspensa, revogada ou expirada, pacote revogado, downgrade, isolamento entre tenants e pacotes adulterados.

## Como funciona

```text
Publicador                     Control Plane                      Cliente
 |  empacota e assina (.sers)      |                                 |
 |-------- registra pacote ------->|                                 |
 |                                 |<-- registra chave + licença ----|
 |                                 |<-- pede desafio (chave efêmera)-|
 |                                 |--- desafio (nonce aleatório) -->|
 |                                 |<-- resposta assinada -----------|
 |                                 |  licença, revogação, versão,    |
 |                                 |  política, atestação: tudo ok?  |
 |                                 |--- autorização assinada + ------>|
 |                                 |    chave do pacote selada       |
```

- O desafio é guardado no servidor e consumido na primeira verificação. Relógios do cliente nunca são usados como prova de frescor.
- A autorização é curta (300 s por padrão), assinada e válida só para uma aplicação, uma instalação e um pacote.
- A chave do pacote só sai do Key Broker no último passo, depois de todas as verificações, selada para a chave efêmera que estava dentro do desafio assinado.
- `hardware_required` exige atestação de hardware verificada pelo servidor. Nenhum verificador real existe, então essa política sempre nega. Nunca há rebaixamento silencioso para software.

## Política de execução

| Política | Efeito |
|---|---|
| `software_allowed` | Execução local com isolamento de software (backend ainda não implementado). |
| `hardware_required` | Exige TEE com atestação verificada. Hoje sempre nega. |
| `remote_execution_required` | Nenhuma chave vai para o cliente; a operação deve rodar em infraestrutura da empresa (ainda não implementado). |

## Estado dos componentes

Todos os itens escritos estão **NOT VERIFIED**: nenhum foi compilado ou executado. Nada pode ser marcado como IMPLEMENTED antes de os testes rodarem.

| Componente | Estado |
|---|---|
| `sers-core`: erros, identificadores, política de execução | NOT VERIFIED |
| `sers-crypto`: SHA-256, Ed25519, X25519, HKDF, AES-256-GCM | NOT VERIFIED |
| `sers-protocol`: mensagens, codec, desafio, autorização, liberação de chave | NOT VERIFIED |
| `sers-identity`: identidade da instalação, prova de posse, arquivo de chave (Unix) | NOT VERIFIED |
| `sers-package`: formato `.sers`, assinatura, criptografia por envelope | NOT VERIFIED |
| `sers-loader`: confiança por publicador, downgrade, revogação | NOT VERIFIED |
| `sers-platform`: detecção de dispositivos e inventário de backends | NOT VERIFIED |
| `sers-controlplane`: autorização, licenças, Key Broker, revogação, auditoria (memória) | NOT VERIFIED |
| Esquema PostgreSQL (`control-plane/migrations`) | NOT VERIFIED (nunca executado) |
| Gateway HTTP, TLS, limite de taxa | NOT IMPLEMENTED |
| Armazenamento PostgreSQL | NOT IMPLEMENTED |
| Provedores KMS e HSM (só existe um provedor de desenvolvimento em memória) | NOT IMPLEMENTED |
| Runtime `sersd`, IPC, backend de software, ABI de módulo | NOT IMPLEMENTED |
| Backends TEE (SGX, TDX, SEV-SNP, TrustZone) e atestação | NOT IMPLEMENTED, REQUIRES HARDWARE |
| Execução remota | NOT IMPLEMENTED |
| SDK, CLI, dashboard | NOT IMPLEMENTED |
| Fuzzing, `cargo audit`, SBOM, assinatura de releases | NOT IMPLEMENTED |

Tecnologias TEE suportadas: **nenhuma**. O `sers-platform` apenas percebe nós de dispositivo, o que não prova atestação nem capacidade.

## Responsabilidades dos módulos

| Módulo | Responsabilidade |
|---|---|
| `sers-core` | Vocabulário comum e a decisão de execução que nunca rebaixa. |
| `sers-crypto` | Única fachada criptográfica; nenhuma primitiva própria. |
| `sers-protocol` | Mensagens versionadas e estritas; bytes canônicos com separação de domínio. |
| `sers-identity` | Chave da instalação e prova de posse no registro. |
| `sers-package` | Formato binário `.sers` sem caminhos nem compressão. |
| `sers-loader` | Recusa pacotes de publicador desconhecido, revogados ou antigos. |
| `sers-platform` | Sondagem do host; não declara capacidades que não existem. |
| `sers-controlplane` | Decide, libera chaves, revoga e audita; isolamento entre tenants. |

## Documentação

Os documentos técnicos estão em inglês.

- [Arquitetura](docs/ARCHITECTURE.md)
- [Modelo de ameaças (STRIDE)](docs/THREAT_MODEL.md)
- [Protocolo](docs/PROTOCOL.md)
- [Criptografia](docs/CRYPTOGRAPHY.md)
- [Formato `.sers`](docs/PACKAGE_FORMAT.md)
- [Suporte a TEE](docs/TEE_SUPPORT.md)
- [Limitações](docs/LIMITATIONS.md)
- [Desenvolvimento](docs/DEVELOPMENT.md)
- [Decisões de arquitetura (ADRs)](docs/adr)

## Testes

```sh
cargo fmt --all
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

O workflow em [`.github/workflows/ci.yml`](.github/workflows/ci.yml) compila e testa em Linux e Windows. As etapas de `fmt` e `clippy` ainda não bloqueiam o build, porque o código nunca passou por elas. O primeiro resultado do CI será a primeira compilação real do projeto.

## Colaboração e estado do GitHub

- Veja [como contribuir](CONTRIBUTING.md), a [política de segurança](SECURITY.md), o [backlog proposto de issues](docs/ISSUE_BACKLOG.md), os [problemas conhecidos](docs/KNOWN_ISSUES.md), o [plano](ROADMAP.md) e o [histórico](CHANGELOG.md).
- O backlog contém propostas locais, não issues já criadas no GitHub.
- Este projeto ainda não tem uma licença escolhida. Antes de distribuir publicamente, o proprietário deve decidir e adicionar o arquivo `LICENSE` correspondente.
