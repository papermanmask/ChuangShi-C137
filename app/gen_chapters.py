# -*- coding: utf-8 -*-
"""调用 /api/generate 流式生成章节，打印 SSE 进度。用法：
   python gen_chapters.py <book> <mode> [target|chapter]
   mode: next / auto / rewrite
"""
import json, sys, urllib.request

def main():
    book, mode = sys.argv[1], sys.argv[2]
    payload = {"book": book, "mode": mode}
    if mode == "auto":
        payload["target"] = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    elif mode == "rewrite":
        payload["chapter"] = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8787/api/generate",
        data=data, headers={"Content-Type": "application/json"})
    resp = urllib.request.urlopen(req, timeout=1200)
    for line in resp:
        s = line.decode("utf-8", "replace").rstrip()
        if s:
            print(s, flush=True)

if __name__ == "__main__":
    main()
