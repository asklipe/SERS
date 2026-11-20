# Histórico

## Não lançado

- Escritos sem compilador (NOT VERIFIED): `sers-sdk`, alvos de fuzzing em `fuzz/`, job `fuzz-smoke` no CI e os documentos de SDK, ABI de módulo, runtime, backends, API HTTP e deployment.
- Validação inicial do workspace em Windows x64: build, 143 testes, Clippy e formatação.
- Corrigidos avisos de Clippy, contratos de enumeração e uso de símbolos específicos de Unix.
- Adicionado CLI `sers` para `backend detect` e inspeção segura de pacotes.
- Adicionado `sers package build` com configuração JSON estrita, limites de entrada, chaves em arquivos binários e validação de assinatura/integridade antes da gravação.
- Migration PostgreSQL agora tem teste CI para isolamento RLS e funções de resolução pré-autenticação.
- Adicionados `Cargo.lock` e política de dependências `deny.toml`; RustSec audit e cargo-deny passaram.
- CI agora bloqueia falhas de formatação e Clippy.
- Migration PostgreSQL, Linux CI, runtime e gateway continuam pendentes.
