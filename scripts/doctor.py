"""Read-only local runtime and connection diagnostics; never changes firewall/proxy settings."""
import argparse,importlib.util,json,socket,sys,urllib.request,urllib.error
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

def diagnose(port):
    checks = {"python":sys.version.split()[0],"dependencies":{name:importlib.util.find_spec(name) is not None for name in ('flask','waitress','pytest')},"url":f"http://127.0.0.1:{port}"}
    try:
        # Bypass HTTP proxy settings only for this loopback diagnostic.
        client=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with client.open(checks['url']+'/health',timeout=3) as response:
            payload=json.load(response)
        checks['server']='healthy' if payload.get('status')=='ok' else 'unexpected health response'
    except urllib.error.HTTPError as exc:
        checks['server']='authentication required' if exc.code==401 else f'HTTP {exc.code}'
    except (OSError,ValueError) as exc:
        checks['server']='unreachable'
        checks['detail']=str(exc)
    return checks

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--port',type=int,default=5000)
    args=parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('Port must be between 1 and 65535')
    checks=diagnose(args.port)
    print(json.dumps(checks,indent=2))
    if checks['server']=='unreachable':
        print('Start python serve.py in another terminal. If port 5000 is occupied, use --port 5010 in both commands. Keep the server terminal open. Use a normal browser; iframe embedding is intentionally blocked.')
    raise SystemExit(0 if checks['server'] in {'healthy','authentication required'} else 1)
