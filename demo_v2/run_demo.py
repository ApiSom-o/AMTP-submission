"""Start the whole demo: Root Anchor, Cloud Server, network path, client. One command:

    ./run_demo.sh                              # 4 domains x 5,000 real files (about 1.5 minutes to load)
    ./run_demo.sh --files-per-domain 500       # smaller set for a rehearsal
    ./run_demo.sh --domains D1,D2

Four separate processes. Stop with Ctrl-C.
"""
import argparse
import os
import signal
import subprocess
import sys
import time
import urllib.request
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))


def wait_up(url, proc, timeout=60):
    """Launcher only: poll until a process answers (this is not part of any measured step)."""
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            raise SystemExit(f"a demo process stopped during start-up (exit {proc.returncode}): {url}")
        try:
            urllib.request.urlopen(url, timeout=1).read()
            return
        except Exception:
            time.sleep(0.2)
    raise SystemExit(f"timed out waiting for {url}")


def start_stack(files_per_domain=5000, domains="D1,D2,D3,D4", base_port=8101, quiet=False):
    """Returns (processes, urls). Ports: base = server, +1 client, +2 anchor, +3 network path."""
    env = dict(os.environ)
    env.pop("AMTP_GAMMA_V", None)                     # the demo always runs the paper's γ (with v)
    u = {"server": f"http://127.0.0.1:{base_port}", "client": f"http://127.0.0.1:{base_port + 1}",
         "anchor": f"http://127.0.0.1:{base_port + 2}", "network": f"http://127.0.0.1:{base_port + 3}"}
    out = subprocess.DEVNULL if quiet else None

    def run(script, *args):
        return subprocess.Popen([sys.executable, os.path.join(HERE, script), *map(str, args)],
                                cwd=HERE, env=env, stdout=out, stderr=out)

    procs = []
    try:
        procs.append(run("anchor_app.py", "--port", base_port + 2))
        wait_up(u["anchor"] + "/health", procs[-1])
        procs.append(run("server_app.py", "--port", base_port))
        wait_up(u["server"] + "/health", procs[-1])
        procs.append(run("mitm_app.py", "--port", base_port + 3, "--server", u["server"]))
        wait_up(u["network"] + "/health", procs[-1])
        procs.append(run("client_app.py", "--port", base_port + 1, "--server", u["server"], "--search", u["network"],
                         "--anchor", u["anchor"], "--files-per-domain", files_per_domain, "--domains", domains))
        wait_up(u["client"] + "/api/status", procs[-1], timeout=120)
    except BaseException:
        stop_stack(procs)
        raise
    return procs, u


def stop_stack(procs):
    for p in procs:
        if p.poll() is None:
            p.send_signal(signal.SIGTERM)
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files-per-domain", type=int, default=5000, help="real files loaded per domain (default 5000)")
    ap.add_argument("--domains", default="D1,D2,D3,D4")
    ap.add_argument("--base-port", type=int, default=8101)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))   # stop the children too
    procs, u = start_stack(a.files_per_domain, a.domains, a.base_port)
    print(f"\nAMTP demo v2\n  open       {u['client']}\n  server     {u['server']}\n  anchor     {u['anchor']}"
          f"\n  network    {u['network']}\n  loading {a.files_per_domain:,} real files per domain ({a.domains}); "
          "the page shows the progress.\n  Ctrl-C to stop.\n", flush=True)
    if not a.no_browser:
        webbrowser.open(u["client"])
    try:
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop_stack(procs)


if __name__ == "__main__":
    main()
