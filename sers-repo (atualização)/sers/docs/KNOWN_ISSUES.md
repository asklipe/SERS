# Problemas conhecidos

1. A validação local executada até agora foi no Windows x64. Linux CI e testes do keystore Unix continuam pendentes.
2. O Control Plane guarda tudo em memória; reiniciar o processo perde tenants, licenças e pacotes.
3. O provedor de chaves de desenvolvimento mantém a chave mestra em memória e não deve proteger nada real.
4. O armazenamento de chave da instalação é um arquivo `0600` (somente Unix). No Windows retorna `Unsupported`.
5. A revogação vale a partir da próxima autorização; autorizações já emitidas valem até expirar (300 s por padrão).
6. `hardware_required` não pode ser concedido: não existe verificador de atestação real.
7. Falta limite de taxa, TLS e qualquer transporte de rede.
8. Cargo-deny reporta uma duplicata não bloqueante de `syn` 2.x/3.x.
9. A migration PostgreSQL e o smoke test de RLS estão configurados para CI, mas ainda não foram executados; PostgreSQL/Docker não estão disponíveis localmente.
10. `sers package build` aceita arquivos crus de chave de 32 bytes já provisionados; o CLI não gera/protege esses arquivos e uma falha de escrita pode deixar a saída parcial.
11. O RLS usa `sers.tenant_id`, uma configuração de sessão que o próprio login SQL pode alterar. É defesa em profundidade contra consultas malformadas, não uma barreira contra login comprometido ou SQL arbitrário; o gateway precisa vincular o tenant após autenticação.
12. Veja a lista completa em [`LIMITATIONS.md`](LIMITATIONS.md) e as ameaças abertas em [`THREAT_MODEL.md`](THREAT_MODEL.md).
