import re
import zstd
import gzip
import brotli
import asyncio

from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster


BANNED = [           # Блокировка хостов и URL
    # HOST
        # {"type": "AD", "qtype": 0, "q": "aj1907.online"},
        # {"type": "AD", "qtype": 0, "q": "adlook.me"},
        {"type": "AD", "qtype": 0, "q": "ad.mail.ru"},
        # {"type": "AD", "qtype": 0, "q": "s2517.com"},
        # {"type": "Tracker", "qtype": 0, "q": "stats.vk-portal.net"},
        # {"type": "Tracker", "qtype": 0, "q": "vak345.com"},
        # {"type": "Tracker", "qtype": 0, "q": "adpod.in"},
        # {"type": "Tracker", "qtype": 0, "q": "google-analytics.com"},
        # {"type": "Tracker", "qtype": 0, "q": "top-fwz1.mail.ru"},
        # {"type": "Tracker", "qtype": 0, "q": "adfox.ru"},
        # {"type": "Tracker", "qtype": 0, "q": "track.smachnakittchen.com"},
        # {"type": "Tracker", "qtype": 0, "q": "log.strm.yandex.ru"},
        # {"type": "Tracker", "qtype": 0, "q": "statika.mpsuadv.ru"},
        # {"type": "Tracker", "qtype": 0, "q": "ssrv7.com"},
        # {"type": "Tracker", "qtype": 0, "q": "stats.rip"},
        # {"type": "Tracker", "qtype": 0, "q": "mixpanel.com"},
        # {"type": "Tracker", "qtype": 0, "q": "tns-counter.ru"},
        # {"type": "Tracker", "qtype": 0, "q": "analytics.google.com"},
        # {"type": "Tracker", "qtype": 0, "q": "counter.yadro.ru"},
    # URL
        {"type": "AD", "qtype": 2, "q": "yandex.ru/ads"},
        # {"type": "AD", "qtype": 2, "q": "a.magsrv.com/ad-provider.js"},
        # {"type": "Tracker", "qtype": 2, "q": "yandex.ru/an/rtbcount"},
        # {"type": "Tracker", "qtype": 2, "q": "yandex.ru/metrika"},
        # {"type": "Tracker", "qtype": 2, "q": "yandex.ru/clck/jclck/"},
        # {"type": "Tracker", "qtype": 2, "q": "yandex.ru/clck/click"},
        # {"type": "Tracker", "qtype": 2, "q": "static-mon.yandex.net/advert"},
        # {"type": "Tracker", "qtype": 2, "q": "api.insertunit.ws/ping/"},
]


STREAM_TRUE = {
    "image", "webm", "svg"
    "video", "mp4", "mp2t", "wasm",
    "octet-stream", "font"
}
STREAM_FALSE = {
    "html", "xml", "css",
    "javascript", "js",
    "json"
}

DECOMPRESSORS = {
    'gzip': (gzip.decompress, gzip.compress),
    'deflate': (gzip.decompress, gzip.compress),
    'br': (brotli.decompress, brotli.compress),
    'zstd': (zstd.decompress, zstd.compress)
}


class CustomHandlers:
    def __init__(self):
        host_patterns = []
        substr_patterns = []

        for item in BANNED:
            if item['qtype'] == 0:
                host_patterns.append(re.escape(item['q']))
            elif item['qtype'] == 2:
                substr_patterns.append(re.escape(item['q']))

        group1 = f"^(?:{'|'.join(host_patterns)})(?:/|$)"
        group2 = f".*(?:{'|'.join(substr_patterns)}).*"
        self.ban_regex = re.compile(rf"({group1})|((?!{group1}).*{group2})", re.IGNORECASE)

    async def requestheaders(self, flow: http.HTTPFlow):
        full_url = flow.request.host + flow.request.path

        match = self.ban_regex.search(full_url)

        if not match:
            return

        matches = match.groups()

        if matches[0]:
            print(f"banned by HOST: {matches[0]}")
        elif matches[1]:
            print(f"banned by PATH: {matches[1][:30]}")
        else:
            return print(f"NOT MATCHES [{matches}] -> {full_url[:30]}")

        flow.kill()

    async def responseheaders(self, flow: http.HTTPFlow):
        ctype = flow.response.headers.get("content-type", "").lower()

        if any(t in ctype for t in STREAM_FALSE):
            flow.response.stream = False
            return
        elif any(t in ctype for t in STREAM_TRUE):
            flow.response.stream = True
            return
        elif ctype:
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
