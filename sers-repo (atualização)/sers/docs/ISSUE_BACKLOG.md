# Backlog proposto de issues

Propostas locais. Nenhuma foi criada no GitHub.

## Prioridade 0 (baseline validada em Windows x64; migration CI pendente)

1. **Primeira compilação.** Concluída em Windows x64; 143 testes, Clippy e formatação passaram. Linux CI pendente.
2. **Executar o esquema SQL** em um PostgreSQL descartável e corrigir.
3. **Escolher a licença** e adicionar `LICENSE` antes de distribuir publicamente.

## Núcleo

4. Gateway HTTP (Axum): autenticação por API key, validação, IDs de requisição, cabeçalhos de segurança, limite de taxa, TLS 1.3.
5. Trait `Store` assíncrona e armazenamento PostgreSQL (consumo de desafio com `DELETE ... RETURNING`).
6. Runtime `sersd`: IPC por socket Unix com credenciais do par, gestão de sessão, aplicação da expiração do token e proteção contra relógio retrocedido.
7. Especificar a ABI de módulo e a fronteira entre host não confiável e núcleo protegido.
8. Backend de software: processo separado, seccomp, namespaces, limites de recurso, relatando só os controles realmente aplicados.
9. CLI `sers` e `sers-cli`: `backend detect`, `inspect` e `package build` estão implementados; identidade e registro ainda pendentes. JSON e códigos de saída já são usados.
10. SDK Rust e ABI C estável; bindings Node.js depois.

## Segurança

11. Fuzzing: parser de pacote, manifesto, decodificação de protocolo, mensagens de IPC.
12. Provedores KMS e HSM para `KeyProvider` e `TokenSigner`; armazenamento de chave da instalação em TPM, Secure Enclave ou DPAPI.
13. Rotação de chaves de pacote e de publicador; log de transparência.
14. `cargo audit` e `cargo deny` passam localmente e rodam no CI; faltam SBOM, assinatura de releases (Sigstore) e proveniência (SLSA).
15. Plano de testes defensivos contra Ghidra, Frida, GDB e outras ferramentas, em ambiente autorizado.

## Hardware

16. Estudo de viabilidade e escolha do primeiro backend TEE conforme o hardware disponível.
17. Verificador de atestação real e liberação de chave ligada ao ambiente atestado.
18. Execução remota para operações que exigem confidencialidade forte.
