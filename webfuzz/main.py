#!/usr/bin/env python3
"""
webfuzz : Automatisation gobuster pour HackTheBox

Usage:
    webfuzz -u http://$DOMAIN                  # dir + vhost
    webfuzz -u http://$DOMAIN --mode dir
    webfuzz -u http://$DOMAIN --mode vhost
    webfuzz -u http://$DOMAIN --from-size medium
    webfuzz -u http://$DOMAIN -x php,html -t 80
    webfuzz -u http://$DOMAIN -- --follow-redirect
"""

import argparse
import subprocess
import sys
import os
import shutil
import threading
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────
#  ANSI
# ─────────────────────────────────────────────────────────────
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
M    = "\033[95m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

VHOST_COLORS = [C, Y, M]

# ─────────────────────────────────────────────────────────────
#  Wordlists
# ─────────────────────────────────────────────────────────────
DIR_WORDLISTS = [
    {"name": "fuzz",   "path": "/opt/lists/seclists/fuzz.txt",
     "label": "fuzz.txt"},
    {"name": "common", "path": "/opt/lists/seclists/Discovery/Web-Content/common.txt",
     "label": "common.txt"},
    {"name": "medium", "path": "/opt/lists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
     "label": "DirBuster medium"},
    {"name": "big",    "path": "/opt/lists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt",
     "label": "DirBuster big"},
]

VHOST_WORDLISTS = [
    {"name": "namelist", "path": "/opt/lists/seclists/Discovery/DNS/namelist.txt",
     "label": "namelist.txt"},
    {"name": "top1m",    "path": "/opt/lists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
     "label": "top1million"},
    {"name": "combined", "path": "/opt/lists/seclists/Discovery/DNS/combined_subdomains.txt",
     "label": "combined_subdomains"},
]

DIR_SIZE_MAP = {"fuzz": 0, "small": 0, "common": 1, "medium": 2, "big": 3}

# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────
print_lock = threading.Lock()

def lprint(msg, end="\n"):
    with print_lock:
        print(msg, end=end, flush=True)

def info(msg):  lprint(f"  {B}[*]{RST} {msg}")
def ok(msg):    lprint(f"  {G}[+]{RST} {msg}")
def warn(msg):  lprint(f"  {Y}[!]{RST} {msg}")
def err(msg):   lprint(f"  {R}[X]{RST} {msg}")

def section(title):
    lprint(f"\n{M}{BOLD}{'━'*56}{RST}")
    lprint(f"{M}{BOLD}  {title}{RST}")
    lprint(f"{M}{BOLD}{'━'*56}{RST}")

def progress_header(label, idx, total):
    lprint(f"\n  {B}[{idx}/{total}]{RST}  {W}{BOLD}{label}{RST}")

def extract_host(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    return host.replace(":", "_")

def outfile_name(outdir: Path, kind: str, host: str, wordlist_name: str) -> str:
    return str(outdir / f"webfuzz_{kind}_{host}_{wordlist_name}.txt")

def show_findings(outfile: str, label: str, color: str = G):
    try:
        with open(outfile) as f:
            lines = [l.rstrip() for l in f if l.strip() and not l.startswith("#")]
        n = len(lines)
        if n:
            ok(f"{G}{BOLD}{n} résultat(s){RST} - {label} :")
            for l in lines:
                lprint(f"      {color}->{RST}  {l}")
        else:
            lprint(f"      {DIM}Rien trouvé.{RST}")
        return n
    except FileNotFoundError:
        return 0

def check_wordlist(path: str) -> bool:
    if not os.path.isfile(path):
        warn(f"Wordlist introuvable, skip : {DIM}{path}{RST}")
        return False
    return True

def banner(url, host, mode, threads, outdir):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    lprint(f"""
{B}{BOLD}╔══════════════════════════════════════════════════════╗
║              webfuzz  ·  HTB recon tool              ║
╚══════════════════════════════════════════════════════╝{RST}
  {DIM}started {ts}{RST}

  {B}Cible   {RST}: {C}{url}{RST}
  {B}Host    {RST}: {C}{host}{RST}
  {B}Mode    {RST}: {Y}{mode}{RST}
  {B}Threads {RST}: {threads}
  {B}Output  {RST}: {C}{outdir}{RST}
""")

# ─────────────────────────────────────────────────────────────
#  DIR runner (pas de PIPE, barre de progression native)
# ─────────────────────────────────────────────────────────────
def run_dir_gobuster(url, wordlist, outfile, threads, extensions, insecure, extra_args):
    cmd = ["gobuster", "dir",
           "-u", url,
           "-w", wordlist,
           "-o", outfile,
           "-t", str(threads),
           "--no-error"]
    if extensions:
        cmd += ["-x", extensions]
    if insecure:
        cmd += ["-k"]
    cmd += extra_args

    info(f"Output -> {C}{outfile}{RST}")
    info(f"Cmd    : {DIM}{' '.join(cmd)}{RST}\n")

    try:
        proc = subprocess.run(cmd)
        return proc.returncode
    except FileNotFoundError:
        err("gobuster introuvable dans le PATH.")
        sys.exit(1)
    except KeyboardInterrupt:
        lprint(f"\n  {Y}[!]{RST} Interrompu (Ctrl+C)")
        return -1


# ─────────────────────────────────────────────────────────────
#  DIR séquentiel
# ─────────────────────────────────────────────────────────────
def run_dir_enum(url, host, outdir, threads, extensions, insecure, start_index, extra_args):
    section("DIR enumeration")
    wordlists = DIR_WORDLISTS[start_index:]
    total = len(wordlists)

    for i, wl in enumerate(wordlists, 1):
        if not check_wordlist(wl["path"]):
            continue

        progress_header(f"[dir] {wl['label']}", i, total)
        outfile = outfile_name(outdir, "dir", host, wl["name"])

        run_dir_gobuster(url, wl["path"], outfile, threads, extensions, insecure, extra_args)

        lprint("")
        show_findings(outfile, wl["label"])


# ─────────────────────────────────────────────────────────────
#  VHOST worker (silencieux, output vers fichier seulement)
# ─────────────────────────────────────────────────────────────
def _vhost_worker(wl, url, host, outdir, threads, insecure, extra_args, color, results):
    if not check_wordlist(wl["path"]):
        results[wl["name"]] = 0
        return

    outfile = outfile_name(outdir, "vhost", host, wl["name"])
    cmd = ["gobuster", "vhost",
           "-u", url,
           "-w", wl["path"],
           "--append-domain",
           "-o", outfile,
           "-t", str(threads),
           "--no-error"]
    if insecure:
        cmd += ["-k"]
    cmd += extra_args

    lprint(f"  {color}[vhost/{wl['label']}]{RST} démarré -> {C}{outfile}{RST}")
    try:
        with open(os.devnull, "w") as devnull:
            subprocess.run(cmd, stdout=devnull, stderr=devnull)
    except FileNotFoundError:
        err("gobuster introuvable.")
        results[wl["name"]] = 0
        return
    except KeyboardInterrupt:
        results[wl["name"]] = 0
        return

    n = 0
    try:
        with open(outfile) as f:
            n = sum(1 for l in f if l.strip() and not l.startswith("#"))
    except FileNotFoundError:
        pass

    results[wl["name"]] = n
    lprint(f"  {color}[vhost/{wl['label']}]{RST} terminé - {G}{BOLD}{n} résultat(s){RST}")


# ─────────────────────────────────────────────────────────────
#  main
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="webfuzz : dir séquentiel + vhost parallèle.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  webfuzz -u http://$DOMAIN
  webfuzz -u http://$DOMAIN --mode dir
  webfuzz -u http://$DOMAIN --mode vhost
  webfuzz -u http://$DOMAIN --from-size medium
  webfuzz -u http://$DOMAIN -x php,html,txt -t 80
  webfuzz -u http://$DOMAIN -- --follow-redirect --timeout 10s
        """,
    )
    parser.add_argument("-u", "--url", required=True,
                        help="URL cible (ex: http://$DOMAIN)")
    parser.add_argument("--mode", choices=["dir", "vhost", "all"], default="all",
                        help="Mode (défaut: all)")
    parser.add_argument("--from-size", choices=list(DIR_SIZE_MAP.keys()),
                        default="fuzz", dest="from_size",
                        help="Wordlist dir de départ (défaut: fuzz)")
    parser.add_argument("-t", "--threads", type=int, default=40)
    parser.add_argument("-x", "--extensions",
                        help="Extensions dir (ex: php,html,txt)")
    parser.add_argument("-o", "--outdir",
                        help="Dossier de sortie (défaut: répertoire courant)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="Skip TLS certificate verification (HTTPS non sécurisé)")
    parser.add_argument("extra", nargs=argparse.REMAINDER,
                        help="Args extra passés à gobuster (après --)")
    args = parser.parse_args()

    extra_args = [a for a in args.extra if a != "--"]

    if not shutil.which("gobuster"):
        err("gobuster introuvable dans le PATH.")
        sys.exit(1)

    outdir = Path(args.outdir) if args.outdir else Path.cwd()
    outdir.mkdir(parents=True, exist_ok=True)

    host = extract_host(args.url)
    banner(args.url, host, args.mode, args.threads, outdir)

    start_index = DIR_SIZE_MAP.get(args.from_size, 0)

    vhost_threads = []
    vhost_results = {}
    if args.mode in ("vhost", "all"):
        section("VHOST enumeration  (3 wordlists en parallèle, background)")
        for wl, color in zip(VHOST_WORDLISTS, VHOST_COLORS):
            t = threading.Thread(
                target=_vhost_worker,
                args=(wl, args.url, host, outdir, args.threads, args.insecure, extra_args, color, vhost_results),
                daemon=True,
            )
            vhost_threads.append((t, wl, color))
            t.start()

    if args.mode in ("dir", "all"):
        run_dir_enum(
            url=args.url, host=host, outdir=outdir,
            threads=args.threads, extensions=args.extensions,
            insecure=args.insecure, start_index=start_index,
            extra_args=extra_args,
        )

    if vhost_threads:
        if any(t.is_alive() for t, _, _ in vhost_threads):
            lprint(f"\n  {B}[*]{RST} En attente de la fin du vhost...")
        for t, _, _ in vhost_threads:
            t.join()

        section("VHOST - résumé")
        for wl, color in zip(VHOST_WORDLISTS, VHOST_COLORS):
            n = vhost_results.get(wl["name"], 0)
            outfile = outfile_name(outdir, "vhost", host, wl["name"])
            lprint(f"\n  {color}[{wl['label']}]{RST}  -  {G if n else DIM}{n} résultat(s){RST}")
            if n:
                show_findings(outfile, wl["label"], color)

    lprint(f"\n{G}{BOLD}  OK Terminé !{RST}  Output : {C}{outdir}{RST}\n")


if __name__ == "__main__":
    main()
