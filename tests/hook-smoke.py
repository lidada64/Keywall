"""Exercise ordinary git push against local disposable bare repositories only."""
import pathlib
import os
import subprocess
import sys
import tempfile

exe = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parent.parent / '.test-data'
root.mkdir(exist_ok=True)
secret = 'HOOK_FIXTURE_no_access_abcdefgh123456'
phrase = 'Test8Phrase'
env = os.environ.copy()

def call(args, cwd=None, input='', ok=True):
    p = subprocess.run([str(a) for a in args], cwd=cwd, env=env, input=input, text=True,
                       encoding='utf-8', capture_output=True, timeout=40)
    assert (p.returncode == 0) == ok, (args, p.stdout, p.stderr)
    assert secret not in p.stdout + p.stderr
    return p

with tempfile.TemporaryDirectory(prefix="hook space 'quote-", dir=root) as temp:
    folder = pathlib.Path(temp)
    env['GIT_CONFIG_GLOBAL'] = str(folder / 'isolated-gitconfig')
    env['GIT_CONFIG_NOSYSTEM'] = '1'
    vault = folder / 'vault.json'
    def kw(*args, input='', ok=True):
        return call([exe, '--vault', vault, *args], input=input, ok=ok)
    kw('--password-stdin', 'init', input=phrase+'\n')
    kw('--password-stdin', 'add', 'test/dev', '--stdin', input=phrase+'\n'+secret+'\n')
    try:
        repo = folder / 'repo'
        remote = folder / 'remote.git'
        call(['git', 'init', '-b', 'main', repo])
        call(['git', 'init', '--bare', remote])
        def git(*args, ok=True):
            return call(['git', *args], cwd=repo, ok=ok)
        git('config', 'user.name', 'Hook Test')
        git('config', 'user.email', 'fixture@example.invalid')
        git('remote', 'add', 'origin', remote)
        file = repo / 'file.txt'
        file.write_text('clean content\n')
        git('add', '.')
        git('commit', '-m', 'clean')
        hooks = repo / '.git' / 'hooks'
        previous = '#!/bin/sh\nwhile IFS= read -r line; do printf "%s\\n" "$line"; done > original-refs.txt\nprintf "%s\\n" "$1" > original-remote.txt\nexit 0\n'
        (hooks / 'pre-push').write_text(previous, encoding='utf-8')
        kw('hook', 'install', '--repo', repo)
        kw('hook', 'install', '--repo', repo)
        assert 'enabled' in kw('hook', 'status', '--repo', repo).stdout
        locked = git('push', 'origin', 'main', ok=False)
        assert 'Vault locked' in locked.stderr, (locked.stdout, locked.stderr)
        assert not (repo / 'original-refs.txt').exists()
        assert call(['git', '--git-dir', remote, 'show-ref'], ok=False).stdout == ''
        kw('--password-stdin', 'login', input=phrase+'\n')
        git('push', 'origin', 'main')
        assert 'refs/heads/main' in (repo / 'original-refs.txt').read_text()
        assert (repo / 'original-remote.txt').read_text().strip() == 'origin'
        clean_oid = git('rev-parse', 'HEAD').stdout.strip()
        file.write_text(secret)
        git('add', 'file.txt')
        git('commit', '-m', 'fixture secret')
        file.write_text('removed\n')
        git('add', 'file.txt')
        git('commit', '-m', 'removed fixture')
        blocked = git('push', 'origin', 'main', ok=False)
        assert 'stored-key:test/dev' in blocked.stderr
        assert call(['git', '--git-dir', remote, 'rev-parse', 'main']).stdout.strip() == clean_oid
        kw('hook', 'remove', '--repo', repo)
        assert (hooks / 'pre-push').read_text() == previous
        assert not (hooks / 'pre-push.keywall-original').exists()
        assert 'absent' in kw('hook', 'status', '--repo', repo).stdout
        (hooks / 'pre-push').write_text(previous.replace('exit 0', 'exit 7'), encoding='utf-8')
        kw('hook', 'install', '--repo', repo)
        git('push', 'origin', clean_oid + ':refs/heads/guarded', ok=False)
        call(['git', '--git-dir', remote, 'show-ref', '--verify', 'refs/heads/guarded'], ok=False)
        kw('hook', 'remove', '--repo', repo)
        git('config', 'core.hooksPath', 'custom-hooks')
        assert 'core.hooksPath' in kw('hook', 'install', '--repo', repo, ok=False).stderr
        git('config', '--unset', 'core.hooksPath')
        kw('hook', 'install', '--repo', repo)
        with (hooks / 'pre-push').open('a') as f:
            f.write('# user modification\n')
        kw('hook', 'remove', '--repo', repo, ok=False)
    finally:
        kw('lock')

print('Hook checks passed: locked push blocked, clean push allowed, deleted historical key blocked, existing hook input preserved/restored, custom paths and modifications protected, quoted paths supported.')
