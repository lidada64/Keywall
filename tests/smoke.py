"""Exercise the published executable with disposable fixture credentials only."""
import os
import pathlib
import subprocess
import sys
import tempfile
import zipfile

exe = pathlib.Path(sys.argv[1]).resolve()
master_phrase = "Published-Fixture-Passphrase-2026"
secret = "SmokeFixtureToken_XYZabcdefgh0123456789"
env = dict(os.environ, DOTNET_ROOT=str(exe.parent / "nonexistent-runtime"), DOTNET_MULTILEVEL_LOOKUP="0")

with tempfile.TemporaryDirectory(prefix="keywall-smoke-", dir=exe.parent) as folder:
    work = pathlib.Path(folder)
    vault = work / "vault.json"

    def run(args, lines="", expected=0):
        p = subprocess.run([str(exe), "--vault", str(vault), "--password-stdin", *args],
                           input=lines, text=True, encoding="utf-8", capture_output=True,
                           env=env, timeout=30)
        assert p.returncode == expected, (args, p.returncode, p.stdout, p.stderr)
        assert secret not in p.stdout + p.stderr, "plaintext leaked to output"
        return p

    assert "0.1.4" in subprocess.check_output([str(exe), "version"], env=env, text=True)
    run(["init"], master_phrase + "\n")
    run(["add", "smoke/dev", "--stdin"], master_phrase + "\n" + secret + "\n")
    assert "smoke/dev" in run(["find", "smoke"], master_phrase + "\n").stdout
    assert secret not in vault.read_text()
    clean = work / "clean.txt"
    clean.write_text("safe release", encoding="utf-8")
    run(["scan", str(clean)], master_phrase + "\n")
    archive = work / "payload.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("hidden.txt", secret)
    run(["scan", str(archive)], master_phrase + "\n", expected=2)
    run(["reveal", "smoke/dev"], master_phrase + "\n", expected=1)
    backup = work / "backup.kwvault"
    run(["backup", str(backup)], master_phrase + "\n")
    p = subprocess.run([str(exe), "--vault", str(backup), "--password-stdin", "list"],
                       input=master_phrase + "\n", text=True, encoding="utf-8", capture_output=True, env=env, timeout=30)
    assert p.returncode == 0 and "smoke/dev" in p.stdout and secret not in p.stdout + p.stderr
    run(["info", "smoke/dev"], "incorrect-password\n", expected=1)
    run(["remove", "smoke/dev", "--yes"], master_phrase + "\n")
    assert "smoke/dev" not in run(["list"], master_phrase + "\n").stdout

print("Published executable smoke checks passed (12 scenarios, no network uploads).")
