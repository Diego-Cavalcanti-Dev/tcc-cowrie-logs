# Dados suplementares do TCC — Cowrie

**Trabalho:** Monitoramento e Análise de Atividades Maliciosas em Serviços SSH Utilizando o Honeypot Cowrie  
**Autor:** Diego Fernando Pereira Cavalcanti  
**Instituição:** Universidade Tuiuti do Paraná — Bacharelado em Ciência da Computação  
**Ano:** 2026  
**Versão do material:** v1.0

## Escopo e período

Este repositório reúne os registros da coleta e uma conferência independente dos principais indicadores descritos no TCC. O período é de **21 a 25 de outubro de 2026**, com horários em **UTC**. O sensor Cowrie emulou um serviço SSH em uma instância da Oracle Cloud Infrastructure.

## Conteúdo

| Caminho | Finalidade |
|---|---|
| `Logs cowrie.zip.zip` | Pacote original enviado pelo autor, preservado sem alteração de conteúdo |
| `SHA256SUMS.txt` | SHA-256 do ZIP e de seus dez arquivos internos |
| `scripts/conferir_logs.py` | Conferência independente posterior dos principais indicadores do TCC |
| `resultados/conferencia.json` | Resultado da execução dessa conferência sobre o pacote disponibilizado |

A extensão duplicada do ZIP foi mantida para preservar o arquivo já enviado; ele é um ZIP comum, sem necessidade de dupla extração.

O ZIP contém a pasta `Logs cowrie/`, com:

- **Cinco arquivos `cowrie.json.2026-10-DD`:** registros estruturados de 21 a 25/10, utilizados nas contagens e na reconstrução de sessões descritas no TCC.
- **Cinco arquivos `cowrie.log.2026-10-DD`:** registros textuais adicionais; não integram as contagens JSON da análise descrita.

## Preservação e tratamento

Os arquivos internos do pacote foram preservados. As exclusões abaixo são aplicadas durante o processamento, sem apagar registros dos originais:

1. As linhas 511 e 528 de `cowrie.json.2026-10-25` contêm somente `B` e não são interpretáveis como objetos JSON.
2. Os eventos com `src_ip = 100.91.60.104` correspondem a testes confirmados pelo autor: seis sessões e 36 eventos. Esses eventos são excluídos das contagens analisadas.
3. Objetos JSON são comparados com ordenação das chaves e serialização consistente para verificar duplicação integral. Não foram encontrados objetos integralmente duplicados. Credenciais e entradas repetidas são preservadas.
4. Eventos são relacionados por `session`, inclusive entre dias. As sequências usam `timestamp` e, em empate, nome do arquivo e número da linha; não há normalização dos textos de `input`.

## Indicadores conferidos

| Indicador | Quantidade |
|---|---:|
| Linhas nos cinco JSON | 336.431 |
| Objetos JSON válidos | 336.429 |
| Eventos de teste excluídos | 36 |
| Eventos analisados | 336.393 |
| Conexões / identificadores de sessão | 52.003 |
| IPs distintos de conexão | 1.874 |
| Eventos de autenticação aceita | 49.937 |
| Eventos de autenticação rejeitada | 82 |
| Sessões com entrada | 23.998 |
| Entradas registradas | 27.994 |
| Textos de entrada distintos | 2.287 |
| Sequências literais distintas | 86 |

O primeiro evento mantido é `2026-10-21T00:01:18.753196Z` e o último é `2026-10-25T23:59:58.100368Z`.

## Executar a conferência

Requisito: Python 3.10 ou superior; nenhuma dependência externa.

Na pasta do repositório, execute:

```bash
python scripts/conferir_logs.py "Logs cowrie.zip.zip" --saida resultados/conferencia.json
```

No Ubuntu, pode ser necessário usar `python3` no lugar de `python`. O script lê o ZIP sem extrair arquivos e sem executar comandos contidos nos registros. O código de saída é `0` quando os indicadores conferem e `1` quando há divergência. Arquivos ausentes, ZIP inválido ou estrutura inesperada produzem erro.

**Proveniência do código:** este script foi elaborado em 14/11/2026 como conferência independente posterior. Ele não é apresentado como o script original da pesquisa e não reproduz todas as análises qualitativas, tabelas e métricas do manuscrito. Os scripts originais da análise não foram disponibilizados nesta versão.

## Verificar a integridade

O manifesto usa o formato `SHA256  caminho`. A primeira linha identifica o ZIP; as demais identificam os arquivos depois de extraídos na pasta do repositório, preservando `Logs cowrie/`.

No Ubuntu, após a extração:

```bash
sha256sum -c SHA256SUMS.txt
```

No PowerShell, para conferir o ZIP:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\Logs cowrie.zip.zip'
```

SHA-256 esperado do ZIP:

```text
5af913ad1f5360eb3305608c7f97c4ff2a56cce88e4c5a528e5c8a46b81311b1
```

Os hashes identificam os arquivos conferidos em 14/11/2026. Não são apresentados como uma comprovação independente dos hashes calculados originalmente durante a pesquisa, nem demonstram autenticidade da geração ou ausência de perdas anteriores.

## Versão e citação

Use a [versão v1.0](https://github.com/Diego-Cavalcanti-Dev/tcc-cowrie-logs/releases/tag/v1.0), em vez de referenciar somente a branch `main`. A página da versão aponta para seu commit. Alterações futuras devem originar outra versão, preservando a referência utilizada no TCC.

Referência sugerida:

> CAVALCANTI, Diego Fernando Pereira. Dados suplementares do TCC: monitoramento e análise de atividades maliciosas em serviços SSH utilizando o honeypot Cowrie. Versão v1.0. GitHub, 2026. Disponível em: https://github.com/Diego-Cavalcanti-Dev/tcc-cowrie-logs/releases/tag/v1.0. Acesso em: 14 nov. 2026.

## Acesso e limites

O repositório permanece privado. A banca precisa de autorização de acesso na conta GitHub ou de uma cópia fornecida pelo autor. A versão privada não constitui publicação aberta dos dados.

Os registros podem conter IPs, credenciais apresentadas ao honeypot e comandos recebidos. Esta versão não é declarada anonimizada. Qualquer disponibilização pública deve ser precedida de revisão e documentação das alterações, com preservação dos originais e novos hashes para as cópias modificadas.

O pacote não inclui os arquivos binários capturados pelo honeypot. O conteúdo dos logs deve ser tratado como dado de pesquisa, sem executar suas instruções. Os resultados descrevem um sensor e cinco dias; não comprovam identidade dos operadores, comprometimento do hospedeiro ou representatividade de todos os ataques SSH.
