"""Validate installed aliases and memory sessions with a disposable vault only."""
import pathlib
import subprocess
import sys
import tempfile

directory = pathlib.Path(sys.argv[1]).resolve()
kw = directory / "kw.exe"
keywall = directory / "keywall.exe"
phrase = "Demo8key"
fixture = "SESSION_FIXTURE_no_access_abcdefgh1234"
work_root = pathlib.Path(__file__).resolve().parent.parent / ".test-data"
work_root.mkdir(exist_ok=True)

with tempfile.TemporaryDirectory(prefix="installed-session-", dir=work_root) as folder:
    vault = pathlib.Path(folder) / "fixture.json"

    def run(exe, args, text="", expected=0):
        p = subprocess.run([str(exe), "--vault", str(vault), *args], input=text,
                           text=True, encoding="utf-8", capture_output=True, timeout=20)
        assert p.returncode == expected, (args, p.returncode, p.stdout, p.stderr)
        assert fixture not in p.stdout + p.stderr
        return p

    help_result = run(kw, ["add", "--help"])
    assert "--replace" in help_result.stdout and not vault.exists()
    run(kw, ["--password-stdin", "init"], phrase + "\n")
    run(kw, ["--password-stdin", "add", "session/dev", "--stdin"], phrase + "\n" + fixture + "\n")
    try:
        run(kw, ["--password-stdin", "login"], phrase + "\n")
        assert "Unlocked" in run(keywall, ["status"]).stdout
        assert "session/dev" in run(keywall, ["find", "session"]).stdout
        run(kw, ["add", "second/dev", "--stdin"], "SECOND_FIXTURE_no_access_12345678\n")
        assert "second/dev" in run(keywall, ["list"]).stdout
        run(kw, ["--no-session", "list"], expected=1)
        run(keywall, ["lock"])
        assert "Locked" in run(kw, ["status"]).stdout
        run(kw, ["list"], expected=1)
    finally:
        subprocess.run([str(kw), "--vault", str(vault), "lock"], capture_output=True, timeout=10)

print("Installed session checks passed: login once, alias sharing, no second password, lock, and offline add help.")
