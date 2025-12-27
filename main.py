import re
import zstd
import gzip
import brotli
import asyncio

from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster


BANNED_HOST = [
    "ad.mail.ru",
    "stats.vk-portal.net",
    "top-fwz1.mail.ru",
    "egress.yandex.net",
    "googleads.g.doubleclick.net"
]

BANNED_URL = [
    "yandex.ru/ads",
    "yandex.ru/clck/safeclick",
    "mc.yandex.ru/watch",
    "yandex.ru/search/zero",
    "yastatic.net/nearest.js",
    "yandex.ru/ick/r",
    "yandex.ru/metrika",
]


STREAM_TRUE = {
    "image", "webm", "svg"
    "video", "mp4", "mp2t", "wasm", "vnd.yt-ump",
    "audio",
    "octet-stream", "font", "css",
}

STREAM_FALSE = {
    "html", "xml",
    "javascript", "js",
    "json", "text"
}


DECOMPRESSORS = {
    'gzip': (gzip.decompress, gzip.compress),
    'deflate': (gzip.decompress, gzip.compress),
    'br': (brotli.decompress, brotli.compress),
    'zstd': (zstd.decompress, zstd.compress)
}

host_regex = re.compile(f"^(?:{'|'.join(re.escape(i) for i in BANNED_HOST)})(?:/|$)", re.IGNORECASE)
substr_regex = re.compile(f"({'|'.join(re.escape(i) for i in BANNED_URL)})", re.IGNORECASE)

class CustomHandlers:
    async def requestheaders(self, flow: http.HTTPFlow):
        hostis = host_regex.search(flow.request.host)
        if hostis is not None:
            print(f"banned by HOST: {hostis.group()}")
            return flow.kill()

        pathis = substr_regex.search(flow.request.host + flow.request.path)
        if pathis is not None:
            print(f"banned by PATH: {pathis.group()}")
            return flow.kill()

    async def request(self, flow: http.HTTPFlow):
        1

    async def responseheaders(self, flow: http.HTTPFlow):
        ctype = flow.response.headers.get("content-type", "").lower()

        for t in STREAM_FALSE:
            if t in ctype:
                flow.response.stream = False
                return
        for t in STREAM_TRUE:
            if t in ctype:
                flow.response.stream = True
                return

        if ctype:
            print(f"НЕ ОПРЕДЛЕННЫЙ ТИП -> {ctype}")

        clen = flow.response.headers.get("content-length")
        if clen and int(clen) > 800000:
            flow.response.stream = True
            return

    async def response(self, flow: http.HTTPFlow):
        if not flow.response.raw_content:
            return

        ce = flow.response.headers.get("content-encoding", "").lower()
        if ce in DECOMPRESSORS:
            decompress, compress = DECOMPRESSORS[ce]
            content = decompress(flow.response.raw_content)
        elif flow.response.raw_content[:3] == b"\x1f\x8b\x08": # gzip
            decompress, compress = DECOMPRESSORS["gzip"]
            content = decompress(flow.response.raw_content)
        elif flow.response.raw_content[:4] == b"(\xb5/\xfd": # zstd
            decompress, compress = DECOMPRESSORS["zstd"]
            content = decompress(flow.response.raw_content)
        elif flow.response.raw_content[:4] == b"\x28\xb5\x2f\xfd": # zstd
            decompress, compress = DECOMPRESSORS["zstd"]
            content = decompress(flow.response.raw_content)
        else:
            compress = lambda raw_content: raw_content
            content = flow.response.raw_content

        contentL = content.lower()

        if contentL.startswith(b"<vast") and contentL.endswith(b"/vast>") and b"![cdata" in contentL:
            flow.response.raw_content = b"Banned vastAD content<br>by DestroyerMITM"
            return

        if flow.request.host == "www.softportal.com" and flow.request.path.startswith("/getsoft"):
            content = content.replace(b"Download();", b"")
            content = content.replace(b"var timeEnd = 10;", b"var timeEnd = 0;location.href = url;setTimeout('location.href = backUrl', 2000);")
            flow.response.raw_content = compress(content)
            return

        if b"src=\"https://yandex.ru/ads/system/context.js\"" in contentL:
            content = content.replace(b'src="https://yandex.ru/ads/system/context.js"', b'src=""')
            flow.response.raw_content = compress(content)
            return


async def start_mitmproxy():
    loop = asyncio.get_event_loop()

    master = DumpMaster(None, loop=loop, with_termlog=True, with_dumper=False)
    master.options.add_option(
            "listen_host",
            str,
            "0.0.0.0",
            "Address to bind proxy server(s) to (may be overridden for individual modes, see `mode`).",
    )
    master.options.add_option(
        "listen_port",
        int,
        8989,
        "Port to bind proxy server(s) to (may be overridden for individual modes, see `mode`). "
        "By default, the port is mode-specific. The default regular HTTP proxy spawns on port 8080.",
    )
    master.addons.add(CustomHandlers())

    await master.run()


if __name__ == "__main__":
    asyncio.run(start_mitmproxy())
