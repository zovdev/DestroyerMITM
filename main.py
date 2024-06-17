import asyncio

import zstd
import gzip as gz
import brotli

from time import time
from mitmproxy import http
from sqlite3 import connect
from msgpack import dumps as msgpackDumps
from mitmproxy.tools.dump import DumpMaster



SAVE_REQUESTS = True # Сохранение всех запросов в базу данных
REQUESTS = []        # Хранение запросов перед сохранением

BANNED = [           # Блокировка хостов и URL
    # HOST
        {"type": "AD", "qtype": 0, "q": "aj1907.online"},
        {"type": "AD", "qtype": 0, "q": "adlook.me"},
        {"type": "AD", "qtype": 0, "q": "ad.mail.ru"},
        {"type": "Tracker", "qtype": 0, "q": "stats.vk-portal.net"},
        {"type": "Tracker", "qtype": 0, "q": "vak345.com"},
        {"type": "Tracker", "qtype": 0, "q": "adpod.in"},
        {"type": "Tracker", "qtype": 0, "q": "google-analytics.com"},
        {"type": "Tracker", "qtype": 0, "q": "top-fwz1.mail.ru"},
        {"type": "Tracker", "qtype": 0, "q": "adfox.ru"},
        {"type": "Tracker", "qtype": 0, "q": "track.smachnakittchen.com"},
        {"type": "Tracker", "qtype": 0, "q": "log.strm.yandex.ru"},
        {"type": "Tracker", "qtype": 0, "q": "statika.mpsuadv.ru"},
        {"type": "Tracker", "qtype": 0, "q": "ssrv7.com"},
        {"type": "Tracker", "qtype": 0, "q": "stats.rip"},
        {"type": "Tracker", "qtype": 0, "q": "mixpanel.com"},
        {"type": "Tracker", "qtype": 0, "q": "tns-counter.ru"},
        {"type": "Tracker", "qtype": 0, "q": "analytics.google.com"},
        {"type": "Tracker", "qtype": 0, "q": "counter.yadro.ru"},
    # URL
        {"type": "AD", "qtype": 2, "q": "yandex.ru/ads"},
        {"type": "Tracker", "qtype": 2, "q": "yandex.ru/an/rtbcount"},
        {"type": "Tracker", "qtype": 2, "q": "yandex.ru/metrika"},
        {"type": "Tracker", "qtype": 2, "q": "yandex.ru/clck/jclck/"},
        {"type": "Tracker", "qtype": 2, "q": "yandex.ru/clck/click"},
        {"type": "Tracker", "qtype": 2, "q": "static-mon.yandex.net/advert"},
        {"type": "Tracker", "qtype": 2, "q": "api.insertunit.ws/ping/"},
]



class CustomStream:
    def __init__(self, flow):
        self.flow = flow
        self.flow.response.raw_content = bytearray()

    def __call__(self, chunks):
        self.flow.response.raw_content.extend(chunks)
        return chunks



class CustomHandlers:
    async def requestheaders(self, flow: http.HTTPFlow):
        # Исправление изображений youtube
        if "yt3.ggpht.com" == flow.request.host:
            flow.request.host = "yt4.ggpht.com"
            return

        # Блокировка сложной многослойной ужасной телеметрии yandex
        if "yandex.ru" in flow.request.host:
            if "/search/_crpd/" in flow.request.path:
                if "/events=" in flow.request.path:
                    flow.kill()
                    return
                if "/path=" in flow.request.path:
                    flow.kill()
                    return
                elif "?beacon=1" in flow.request.path:
                    flow.kill()
                    return

        # Блокировка хостов и ссылок
        for b in BANNED:
            by = [flow.request.host, flow.request.path, flow.request.host + flow.request.path][b["qtype"]]

            if b["q"] in by:
                print("banned request >> ", b["q"])
                flow.kill()
                return

    async def request(self, flow: http.HTTPFlow):
        1

    async def responseheaders(self, flow: http.HTTPFlow):
        # Установка стриминга нужных/не нужных для чтения/блокировки запросов
        flow.response.stream = True

        if "content-type" in flow.response.headers:
            ctype = flow.response.headers["content-type"]

            if "image" in ctype:
                return
            elif "video" in ctype:
                return
            elif "mp4" in ctype:
                return
            elif "mp2t" in ctype:
                return
            elif "font" in ctype:
                return
            elif "wasm" in ctype:
                return
            elif "svg" in ctype:
                return
            elif "vnd.yt-ump"in ctype:
                return
            elif "json" in ctype:
                flow.response.stream = False
                return
            elif "html" in ctype:
                flow.response.stream = False
                return
            elif "javascript" in ctype:
                flow.response.stream = False
                return
            elif "css" in ctype:
                flow.response.stream = False
                return
        elif "content-length" in flow.response.headers and int(flow.response.headers["content-length"]) > 800000:
            return

        flow.response.stream = CustomStream(flow)

    async def response(self, flow: http.HTTPFlow):
        if not flow.response.raw_content:
            if SAVE_REQUESTS:
                REQUESTS.append([flow.request.method, flow.request.host, flow.request.path, flow])
            return

        if type(flow.response.raw_content) == bytearray:
            flow.response.raw_content = bytes(flow.response.raw_content)

        if SAVE_REQUESTS:
            REQUESTS.append([flow.request.method, flow.request.host, flow.request.path, flow])

        # Получаем тип кодирования и распаковываем
        content = flow.response.raw_content
        compress = lambda c: c

        if content[:3] == b"\x1f\x8b\x08":
            content = gz.decompress(flow.response.raw_content)
            compress = gz.compress
        elif content[:4] == b"(\xb5/\xfd" or content[:4] == b"\x28\xb5\x2f\xfd":
            content = zstd.decompress(flow.response.raw_content)
            compress = zstd.compress
        elif "content-encoding" in flow.response.headers and "br" in flow.response.headers["content-encoding"]:
            content = brotli.decompress(flow.response.raw_content)
            compress = brotli.compress

        # Блокировка VAST рекламы (очень эффективно)
        cl = content.lower()
        if (b"<vast" in cl and b"/vast>" in cl) and b"![cdata" in cl: # and (b"<ad>" in cl or b"<adsystem>" in cl)
            print("BANNED VAST >> ", flow.request.host + flow.request.path[:30])
            return flow.kill()

        # Удаление ожидания на скачивание softportal
        if flow.request.host == "www.softportal.com" and flow.request.path.startswith("/getsoft"):
            flow.response.raw_content = compress( content.replace(b"var timeEnd = 10;", b"var timeEnd = 1;") )
            return

        # Исправление yandex
        if flow.request.host == "yandex.ru" and flow.request.path.startswith("/search/?text="):
            # я не смог вырезать всё, слишком много мусора в yandex
            startFind = content.find(b"Ya.SerpContext={")
            startFind = content.find(b"<script nonce=", startFind-50, startFind)
            EndFind = content.find(b"</script>", startFind)
            content = content[:startFind] + content[EndFind+9:]

            startFind = content.find(b"Ya.clck=")
            startFind = content.find(b"<script nonce=", startFind-50, startFind)
            EndFind = content.find(b"</script>", startFind)
            content = content[:startFind] + content[EndFind+9:]

            flow.response.raw_content = compress( content )
            return



async def background_write():
    if not SAVE_REQUESTS:
        return

    print("background_write START")

    while True:
        await asyncio.sleep(20)

        if not REQUESTS or len(REQUESTS) < 30:
            continue

        st = time()

        for _ in range(len(REQUESTS)-1):
            tmp = REQUESTS.pop()
            c.execute("""INSERT INTO requests (METHOD, HOST, PATH, FLOW) VALUES (?, ?, ?, ?)""", (tmp[0], tmp[1], tmp[2], msgpackDumps(tmp[3].get_state())))
        conn.commit()

        print(f"DB SAVE > {time() - st}")


async def start_mitmproxy():
    loop = asyncio.get_event_loop()

    master = DumpMaster(None, loop=loop, with_termlog=True, with_dumper=False)
    master.addons.add(CustomHandlers())

    await asyncio.gather(
        master.run(),
        background_write()
    )



if __name__ == "__main__":
    if SAVE_REQUESTS:
        conn = connect("mitm.sql", check_same_thread=False)
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS requests (METHOD text, HOST text, PATH text, FLOW BLOB)""")
        conn.commit()

    asyncio.run(start_mitmproxy())
