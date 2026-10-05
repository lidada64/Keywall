"""Test global guard with an isolated Git config, fixture vault and local remotes."""
import os
import pathlib
import subprocess
import sys
import tempfile

exe = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parent.parent / '.test-data'
root.mkdir(exist_ok=True)
secret = 'GLOBAL_FIXTURE_no_access_abcdefgh123456'
phrase = 'Test8Phrase'

with tempfile.TemporaryDirectory(prefix="global hooks 'space-", dir=root) as temp:
    folder = pathlib.Path(temp)
    env = os.environ.copy()
    env['GIT_CONFIG_GLOBAL'] = str(folder / 'gitconfig')
    env['GIT_CONFIG_NOSYSTEM'] = '1'
    vault = folder / 'vault.json'
    def call(args, cwd=folder, input='', ok=True):
        p = subprocess.run([str(a) for a in args], cwd=cwd, env=env, input=input,
                           text=True, encoding='utf-8', capture_output=True, timeout=40)
        assert (p.returncode == 0) == ok, (args, p.stdout, p.stderr)
        assert secret not in p.stdout + p.stderr
        return p
    def kw(*args, input='', ok=True):
        return call([exe, '--vault', vault, *args], input=input, ok=ok)
    def make_repo(name):
        repo = folder / name
        remote = folder / (name+'.git')
        call(['git', 'init', '-b', 'main', repo])
        call(['git', 'init', '--bare', remote])
        for key, value in [('user.name','Test'),('user.email','fixture@example.invalid')]:
            call(['git', 'config', key, value], cwd=repo)
        call(['git', 'remote', 'add', 'origin', remote], cwd=repo)
        hooks = repo / '.git/hooks'
        (hooks/'pre-push').write_text('#!/bin/sh\nwhile IFS= read -r line; do printf "%s\\n" "$line"; done > prior-push.txt\nexit 0\n')
        (hooks/'pre-commit').write_text('#!/bin/sh\nprintf "ran" > prior-commit.txt\nexit 0\n')
        (repo/'file.txt').write_text('safe content\n')
        call(['git','add','file.txt'],cwd=repo)
        call(['git','commit','-m','clean'],cwd=repo)
        return repo, remote
    kw('--password-stdin','init',input=phrase+'\n')
    kw('--password-stdin','add','test/dev','--stdin',input=phrase+'\n'+secret+'\n')
    existing, remote1 = make_repo('existing')
    try:
        kw('hook','install','--global')
        kw('hook','install','--global')
        assert 'enabled' in kw('hook','status','--global').stdout
        fresh, remote2 = make_repo('created-after-install')
        assert (fresh/'prior-commit.txt').read_text() == 'ran'
        for repo in [existing,fresh]:
            assert 'Vault locked' in call(['git','push','origin','main'],cwd=repo,ok=False).stderr
        kw('--password-stdin','login',input=phrase+'\n')
        for repo in [existing,fresh]:
            call(['git','push','origin','main'],cwd=repo)
            assert 'refs/heads/main' in (repo/'prior-push.txt').read_text()
        before = call(['git','rev-parse','HEAD'],cwd=fresh).stdout.strip()
        (fresh/'file.txt').write_text(secret)
        call(['git','add','file.txt'],cwd=fresh)
        call(['git','commit','-m','fixture'],cwd=fresh)
        assert 'stored-key:test/dev' in call(['git','push','origin','main'],cwd=fresh,ok=False).stderr
        assert call(['git','--git-dir',remote2,'rev-parse','main']).stdout.strip() == before
        kw('lock')
        kw('hook','remove','--global')
        call(['git','config','--global','--get','core.hooksPath'],ok=False)
        prior = folder/'prior global hooks'
        prior.mkdir()
        (prior/'pre-push').write_text('#!/bin/sh\nprintf "ran" > prior-global-push.txt\nexit 7\n')
        call(['git','config','--global','core.hooksPath',prior])
        kw('hook','install','--global')
        kw('--password-stdin','login',input=phrase+'\n')
        existing_oid = call(['git','rev-parse','HEAD'],cwd=existing).stdout.strip()
        call(['git','push','origin',existing_oid+':refs/heads/prior-blocked'],cwd=existing,ok=False)
        assert (existing/'prior-global-push.txt').read_text() == 'ran'
        call(['git','--git-dir',remote1,'show-ref','--verify','refs/heads/prior-blocked'],ok=False)
        kw('hook','remove','--global')
        assert call(['git','config','--global','--get','core.hooksPath']).stdout.strip() == str(prior)
    finally:
        kw('lock')

print('Global checks passed: existing and future repos guarded, locked/leaked pushes blocked, original push and commit hooks forwarded, original global config restored. Real Git config untouched.')
