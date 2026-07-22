import base64, json, os, sys, urllib.request

src = sys.argv[1] if len(sys.argv) > 1 else "build-output-tail.log"
dst = sys.argv[2] if len(sys.argv) > 2 else "last-build-error.log"

repo = os.environ["GITHUB_REPOSITORY"]
token = os.environ["GH_TOKEN"]
sha = os.environ["GITHUB_SHA"]
if not os.path.exists(src):
    print(f"{src} does not exist, skipping publish")
    sys.exit(0)
with open(src, "rb") as f:
    content = f.read()

url = f"https://api.github.com/repos/{repo}/contents/{dst}"
req = urllib.request.Request(url, headers={"Authorization": f"token {token}"})
sha_existing = None
try:
    with urllib.request.urlopen(req) as resp:
        sha_existing = json.load(resp)["sha"]
except Exception:
    pass

payload = {
    "message": f"CI build error log for {sha}",
    "content": base64.b64encode(content).decode(),
    "branch": "main",
}
if sha_existing:
    payload["sha"] = sha_existing

req2 = urllib.request.Request(
    url,
    data=json.dumps(payload).encode(),
    headers={"Authorization": f"token {token}", "Content-Type": "application/json"},
    method="PUT",
)
with urllib.request.urlopen(req2) as resp:
    print(resp.status)
