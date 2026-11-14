#!/usr/bin/env python3
"""Conferência independente posterior à análise do TCC (14/11/2026).
Lê o ZIP sem extrair ou executar comandos contidos nos logs.
Não representa os scripts originais de processamento da pesquisa.
Python 3.10+; somente biblioteca padrão.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
import sys
import zipfile

EXPECTED = {
    "linhas": 336431, "json_validos": 336429, "eventos_excluidos": 36,
    "sessoes_excluidas": 6, "eventos_analisados": 336393,
    "conexoes": 52003, "sessoes": 52003, "ips_distintos": 1874,
    "autenticacoes_aceitas": 49937, "autenticacoes_rejeitadas": 82,
    "sessoes_com_entrada": 23998, "entradas": 27994,
    "entradas_distintas": 2287, "sequencias_distintas": 86,
    "usuarios_distintos": 750, "senhas_distintas": 13850,
    "pares_distintos": 25665, "eventos_arquivo_download": 1023,
    "eventos_arquivo_upload": 68, "objetos_duplicados": 0,
}
DAILY = {
    "2026-10-21": [64696, 8249, 7986, 21, 8049],
    "2026-10-22": [36506, 4796, 4589, 11, 4329],
    "2026-10-23": [42984, 7166, 6798, 13, 2607],
    "2026-10-24": [92533, 15463, 14783, 22, 5646],
    "2026-10-25": [99674, 16329, 15781, 15, 7363],
}
TEST_IP = "100.91.60.104"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("arquivo_zip", type=Path)
    parser.add_argument("--saida", type=Path, help="Salvar relatório JSON neste caminho")
    args = parser.parse_args()
    counts = collections.Counter()
    types = collections.Counter()
    daily = collections.defaultdict(collections.Counter)
    seen = set()
    excluded_sessions = set()
    sessions = set()
    ips = set()
    users, passwords, pairs, inputs = set(), set(), set(), set()
    sequence_inputs = collections.defaultdict(list)
    files, invalid = [], []
    first = last = None
    with zipfile.ZipFile(args.arquivo_zip) as archive:
        names = sorted(n for n in archive.namelist() if Path(n).name.startswith("cowrie.json."))
        expected_names = {"cowrie.json." + day for day in DAILY}
        if len(names) != 5 or {Path(n).name for n in names} != expected_names:
            raise ValueError("O ZIP deve conter exatamente os cinco JSON de 21 a 25/10/2026.")
        for name in names:
            digest = hashlib.sha256()
            lines = 0
            with archive.open(name) as source:
                for line_number, raw in enumerate(source, 1):
                    digest.update(raw)
                    lines += 1
                    counts["linhas"] += 1
                    try:
                        event = json.loads(raw)
                        if not isinstance(event, dict):
                            raise ValueError("Registro não é objeto JSON")
                    except (ValueError, UnicodeDecodeError):
                        invalid.append({"arquivo": Path(name).name, "linha": line_number,
                                        "conteudo": raw.decode("utf-8", errors="replace").strip()})
                        continue
                    counts["json_validos"] += 1
                    normalized = json.dumps(event, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                    object_hash = hashlib.sha256(normalized.encode("utf-8")).digest()
                    counts["objetos_duplicados"] += object_hash in seen
                    seen.add(object_hash)
                    sid, ip = event.get("session"), event.get("src_ip")
                    if ip == TEST_IP:
                        counts["eventos_excluidos"] += 1
                        excluded_sessions.add(sid)
                        continue
                    counts["eventos_analisados"] += 1
                    sessions.add(sid)
                    kind = event.get("eventid")
                    timestamp = event.get("timestamp", "")
                    if timestamp:
                        first = min(first, timestamp) if first else timestamp
                        last = max(last, timestamp) if last else timestamp
                    day = timestamp[:10]
                    daily[day]["eventos"] += 1
                    types[kind] += 1
                    if kind == "cowrie.session.connect":
                        ips.add(ip)
                        daily[day]["conexoes"] += 1
                    if kind in ("cowrie.login.success", "cowrie.login.failed"):
                        daily[day]["aceitas" if kind.endswith("success") else "rejeitadas"] += 1
                        if "password" in event:
                            users.add(event.get("username"))
                            passwords.add(event["password"])
                            pairs.add((event.get("username"), event["password"]))
                    if kind == "cowrie.command.input":
                        daily[day]["entradas"] += 1
                        value = event.get("input")
                        inputs.add(value)
                        sequence_inputs[sid].append((timestamp, name, line_number, value))
            files.append({"arquivo": name, "bytes": archive.getinfo(name).file_size,
                          "linhas": lines, "sha256": digest.hexdigest()})
    sequences = {tuple(row[3] for row in sorted(rows)) for rows in sequence_inputs.values()}
    counts.update({"sessoes_excluidas": len(excluded_sessions), "sessoes": len(sessions),
                   "conexoes": types["cowrie.session.connect"], "ips_distintos": len(ips),
                   "autenticacoes_aceitas": types["cowrie.login.success"],
                   "autenticacoes_rejeitadas": types["cowrie.login.failed"],
                   "sessoes_com_entrada": len(sequence_inputs),
                   "entradas": types["cowrie.command.input"], "entradas_distintas": len(inputs),
                   "sequencias_distintas": len(sequences), "usuarios_distintos": len(users),
                   "senhas_distintas": len(passwords), "pares_distintos": len(pairs),
                   "eventos_arquivo_download": types["cowrie.session.file_download"],
                   "eventos_arquivo_upload": types["cowrie.session.file_upload"]})
    comparisons = {key: {"esperado": value, "obtido": counts[key], "confere": counts[key] == value}
                   for key, value in EXPECTED.items()}
    columns = ["eventos", "conexoes", "aceitas", "rejeitadas", "entradas"]
    daily_ok = all([daily[day][key] for key in columns] == values for day, values in DAILY.items())
    invalid_ok = invalid == [
        {"arquivo": "cowrie.json.2026-10-25", "linha": 511, "conteudo": "B"},
        {"arquivo": "cowrie.json.2026-10-25", "linha": 528, "conteudo": "B"},
    ]
    period_ok = first == "2026-10-21T00:01:18.753196Z" and last == "2026-10-25T23:59:58.100368Z"
    ok = all(item["confere"] for item in comparisons.values()) and daily_ok and invalid_ok and period_ok
    report = {"tipo": "conferencia_independente_posterior", "confere_com_indicadores_tcc": ok,
              "comparacoes": comparisons, "diario_confere": daily_ok,
              "diario": {day: dict(values) for day, values in sorted(daily.items())},
              "linhas_invalidas_conferem": invalid_ok, "linhas_invalidas": invalid,
              "primeiro_evento": first, "ultimo_evento": last, "periodo_confere": period_ok,
              "arquivos_json": files,
              "limite": "Coincidência de indicadores não prova identidade histórica byte a byte."}
    text = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.saida:
        args.saida.parent.mkdir(parents=True, exist_ok=True)
        args.saida.write_text(text, encoding="utf-8")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
