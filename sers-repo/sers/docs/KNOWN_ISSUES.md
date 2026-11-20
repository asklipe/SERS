# Problemas conhecidos

1. **Nada foi compilado.** Espere erros de compilação e testes falhando no primeiro `cargo test`. Os pontos mais prováveis estão listados em `ROADMAP.md`.
2. Os vetores de teste conhecidos (RFC 8032 teste 1, RFC 5869 caso 1, SHA-256 de "abc") foram digitados de memória; um erro de digitação faria o teste falhar sem indicar bug no código.
3. O CI não bloqueia em `fmt` e `clippy` até a primeira execução limpa.
4. O Control Plane guarda tudo em memória; reiniciar o processo perde tenants, licenças e pacotes.
5. O provedor de chaves de desenvolvimento mantém a chave mestra em memória e não deve proteger nada real.
6. O armazenamento de chave da instalação é um arquivo `0600` (somente Unix). No Windows retorna `Unsupported`.
7. A revogação vale a partir da próxima autorização; autorizações já emitidas valem até expirar (300 s por padrão).
8. `hardware_required` não pode ser concedido: não existe verificador de atestação real.
9. Falta limite de taxa, TLS e qualquer transporte de rede.
10. Veja a lista completa em [`LIMITATIONS.md`](LIMITATIONS.md) e as ameaças abertas em [`THREAT_MODEL.md`](THREAT_MODEL.md).
