# Como contribuir

O SERS é um projeto de segurança. Correção e honestidade sobre o que foi verificado valem mais que volume de código.

## Antes de abrir um pull request

1. Rode `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` e `cargo test --workspace`.
2. Cada mudança de comportamento precisa de teste, inclusive o caso negativo (o que deve ser recusado).
3. Não marque algo como funcionando no README, no ROADMAP ou nos docs sem um teste que execute essa afirmação.

## Regras do projeto

- Nada de primitivas criptográficas próprias. Use apenas `sers-crypto`.
- Nada de `unsafe` (o workspace usa `unsafe_code = "forbid"`). Se um dia for inevitável, documente o motivo em um ADR.
- Mensagens de erro são strings estáticas: nunca inclua chaves, texto claro ou dados controlados pelo atacante.
- Dados que passam pela rede ou pelo disco são validados de forma estrita; rejeite o que não for reconhecido.
- Não descreva a proteção de software como equivalente a um TEE e não prometa que a engenharia reversa é impossível.
- Nunca faça rebaixamento silencioso de `hardware_required` para software.
- Não inclua credenciais reais, chaves privadas ou arquivos `.key` em commits.

## Vulnerabilidades

Não abra issue pública. Veja [`SECURITY.md`](SECURITY.md).

## Licença

O projeto ainda não tem licença escolhida; o proprietário precisa decidir antes de aceitar contribuições externas.
