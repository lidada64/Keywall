"""Push boundary regression: ignored working files and already-remote blobs."""
import os
import pathlib
import subprocess
import sys
import tempfile

exe = pathlib.Path(sys.argv[1]).resolve()
root = pathlib.Path(__file__).resolve().parent.parent / '.test-data'
root.mkdir(exist_ok=True)
phrase = 'Fixture8Phrase'
secret = 'IGNORED_ENV_FIXTURE_no_access_abcdef123456'
with tempfile.TemporaryDirectory(prefix='ignored-env-', dir=root) as temp:
    folder = pathlib.Path(temp)
    env = os.environ.copy()
    env['GIT_CONFIG_GLOBAL'] = str(folder/'gitconfig')
    env['GIT_CONFIG_NOSYSTEM'] = '1'
    vault = folder/'vault.json'
    def call(args, cwd=folder, input='', ok=True):
        p = subprocess.run(list(map(str,args)),cwd=cwd,env=env,input=input,text=True,
                           encoding='utf-8',capture_output=True,timeout=40)
        assert (p.returncode == 0) == ok, (args,p.stdout,p.stderr)
        assert secret not in p.stdout+p.stderr
        return p
    def kw(*args,input='',ok=True):
        return call([exe,'--vault',vault,*args],input=input,ok=ok)
    def git(repo,*args,ok=True):
        return call(['git',*args],cwd=repo,ok=ok)
    def setup(name):
        repo=folder/name; remote=folder/(name+'.git')
        call(['git','init','-b','main',repo]); call(['git','init','--bare',remote])
        git(repo,'config','user.name','Fixture'); git(repo,'config','user.email','fixture@example.invalid')
        git(repo,'remote','add','origin',remote)
        return repo,remote
    kw('--password-stdin','init',input=phrase+'\n')
    kw('--password-stdin','add','fixture/env','--stdin',input=phrase+'\n'+secret+'\n')
    try:
        kw('--password-stdin','login',input=phrase+'\n')
        repo,remote=setup('untracked')
        (repo/'.gitignore').write_text('.env\n')
        (repo/'.env').write_text('API_KEY='+secret+'\n')
        (repo/'clean.txt').write_text('safe\n')
        git(repo,'add','.'); git(repo,'commit','-m','ignored fixture')
        kw('hook','install','--repo',repo)
        git(repo,'push','origin','main')
        print('PASS ignored untracked .env does not block push')
        tip=git(repo,'rev-parse','HEAD').stdout.strip()
        missing=kw('git-check','--stdin','--repo',repo,input=f'refs/heads/main {tip} refs/heads/main '+('1'*40)+'\n',ok=False)
        assert 'Run git fetch' in missing.stderr
        print('PASS unavailable remote base fails closed with fetch instructions')
        git(repo,'add','-f','.env'); git(repo,'commit','-m','new leaked fixture')
        git(repo,'rm','--cached','.env'); git(repo,'commit','-m','untrack before push')
        blocked=git(repo,'push','origin','main',ok=False)
        assert 'stored-key:fixture/env' in blocked.stderr
        print('PASS ignored/deleted secret in unpushed history still blocks')
        repo,remote=setup('already-remote')
        (repo/'.env').write_text('API_KEY='+secret+'\n')
        git(repo,'add','.'); git(repo,'commit','-m','old remote fixture')
        git(repo,'push','origin','main')  # Fixture baseline, no guard; local remote only.
        (repo/'.gitignore').write_text('.env\n')
        git(repo,'rm','--cached','.env'); git(repo,'add','.gitignore')
        git(repo,'commit','-m','stop tracking ignored env')
        kw('hook','install','--repo',repo)
        git(repo,'push','origin','main')
        print('PASS already-remote secret blob does not block clean follow-up push')
        (repo/'clean.txt').write_text('safe follow-up\n')
        git(repo,'add','clean.txt'); git(repo,'commit','-m','clean follow-up')
        kw('hook','remove','--repo',repo)  # Verify the standalone entry point independently.
        kw('push','origin','main','--repo',repo)
        print('PASS kw push uses the same outgoing-object boundary')
    finally:
        kw('lock')
