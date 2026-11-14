# -*- coding: utf-8 -*-
"""调用 /api/book/create 流式建书，打印 SSE 进度。"""
import json, sys, urllib.request

def main():
    title, genre, platform, lang, brieffile = sys.argv[1:6]
    brief = open(brieffile, "r", encoding="utf-8").read()
    data = json.dumps({
        "title": title, "genre": genre, "platform": platform,
        "lang": lang, "brief": brief,
    }).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8787/api/book/create",
        data=data, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=900)
    for line in resp:
        s = line.decode("utf-8", "replace").rstrip()
        if s:
            print(s, flush=True)

if __name__ == "__main__":
    main()
