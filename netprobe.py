#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netprobe.py — глубокая диагностика блокировок. Версия 3.

Развитие dnsprobe.py. Отличия:
  * два независимых режима: client (машина за туннелем) и server (VPS);
  * различает ТИП блокировки: DNS-фильтр, подмена, RST по SNI, drop, блок QUIC;
  * знает про туннель — не советует чинить то, что уже работает внутри него;
  * режим compare: сравнивает два прогона (с VPN и без) и показывает разницу.

Только стандартная библиотека. Python 3.7+.

    python3 netprobe.py client --dns 172.29.172.254 --label vpn --json vpn.json
    python3 netprobe.py client --label novpn --json novpn.json
    python3 netprobe.py compare novpn.json vpn.json

    sudo python3 netprobe.py server --json server.json
"""

import argparse
import contextlib
import io
import json
import os
import platform
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.request

TIMEOUT = 5
VERSION = 3

# Домены, на которых держится YouTube. Ломается обычно не главная страница,
# а один из служебных хостов — тогда экран белый, а сайт "как бы открыт".
YT_DOMAINS = [
    "www.youtube.com",        # сама страница
    "youtubei.googleapis.com",  # API плеера, без него белый экран
    "i.ytimg.com",            # превью
    "rr1---sn-4g5e6nzs.googlevideo.com",  # отдача видео
]

# Карта охвата фильтрации: DPI реагирует на ИМЯ в ClientHello независимо
# от того, чей это адрес. Поэтому все имена проверяются на одном и том же
# узле Google — так видно, что именно режется, а что проходит.
SCOPE_SNI = [
    ("www.youtube.com", "YouTube"),
    ("youtubei.googleapis.com", "YouTube API"),
    ("web.telegram.org", "Telegram"),
    ("discord.com", "Discord"),
    ("x.com", "X/Twitter"),
    ("www.instagram.com", "Instagram"),
    ("rutracker.org", "RuTracker"),
    ("www.google.com", "Google (контроль)"),
    ("example.com", "example.com (контроль)"),
]

# Полный список для режима scan. Группы важны: они дают понять не «что
# сломалось у меня», а «какая политика фильтрации в этой сети».
# Проверяется реакция DPI на ИМЯ в ClientHello, поэтому сами сайты
# трогать не нужно — все запросы идут на один и тот же узел.
SCAN_GROUPS = [
    ("Контроль (должно проходить всегда)", [
        ("example.com", "example.com"),
        ("www.google.com", "Google"),
        ("yandex.ru", "Яндекс"),
        ("www.gosuslugi.ru", "Госуслуги"),
    ]),
    ("Видео", [
        ("www.youtube.com", "YouTube"),
        ("youtubei.googleapis.com", "YouTube API"),
        ("i.ytimg.com", "YouTube превью"),
        ("rr1---sn-4g5e6nzs.googlevideo.com", "YouTube отдача видео"),
        ("www.twitch.tv", "Twitch"),
        ("vimeo.com", "Vimeo"),
        ("rutube.ru", "RuTube"),
    ]),
    ("Мессенджеры", [
        ("web.telegram.org", "Telegram"),
        ("api.telegram.org", "Telegram API"),
        ("discord.com", "Discord"),
        ("web.whatsapp.com", "WhatsApp"),
        ("signal.org", "Signal"),
        ("www.viber.com", "Viber"),
    ]),
    ("Соцсети", [
        ("x.com", "X/Twitter"),
        ("www.instagram.com", "Instagram"),
        ("www.facebook.com", "Facebook"),
        ("www.reddit.com", "Reddit"),
    ]),
    ("Шифрованный DNS (ломает всё сразу)", [
        ("dns.google", "Google DoH"),
        ("cloudflare-dns.com", "Cloudflare DoH"),
        ("dns.quad9.net", "Quad9 DoH"),
        ("dns.adguard-dns.com", "AdGuard DoH"),
    ]),
    ("Обходные пути и их точки входа", [
        ("www.cloudflare.com", "Cloudflare"),
        ("speed.cloudflare.com", "Cloudflare Speed"),
        ("bridges.torproject.org", "Tor Bridges"),
        ("snowflake-broker.torproject.net", "Snowflake"),
        ("www.torproject.org", "Tor Project"),
        ("protonvpn.com", "ProtonVPN"),
        ("amnezia.org", "Amnezia"),
    ]),
    ("Почта и облака", [
        ("mail.proton.me", "Proton Mail"),
        ("mail.google.com", "Gmail"),
        ("drive.google.com", "Google Drive"),
    ]),
    ("Разное", [
        ("www.wikipedia.org", "Wikipedia"),
        ("duckduckgo.com", "DuckDuckGo"),
        ("github.com", "GitHub"),
        ("rutracker.org", "RuTracker"),
    ]),
]

CONTROL_DOMAINS = [
    "www.google.com",         # контроль: не блокируется почти нигде
    "example.com",            # контроль: нейтральный
]

PUBLIC_RESOLVERS = [
    ("8.8.8.8", "Google"),
    ("1.1.1.1", "Cloudflare"),
    ("9.9.9.9", "Quad9"),
]

# TEST-NET-1 (RFC 5737). Резолвера там нет и быть не может.
# Любой ответ отсюда = прозрачный перехват DNS на транзите.
# Адреса, по которым резолвера не существует и существовать не может:
# TEST-NET-1/2/3 (RFC 5737), CGNAT (RFC 6598) и зарезервированный частный.
# Проверяем НЕСКОЛЬКО: отдельно взятый адрес может быть просто отброшен
# маршрутизатором, и тогда одиночная проба даст ложное «перехвата нет».
BLACKHOLE_RESOLVERS = ["192.0.2.1", "198.51.100.1", "203.0.113.1",
                       "100.64.0.1", "172.31.255.254"]

DOH_ENDPOINTS = [
    ("https://dns.google/resolve", "dns.google"),
    ("https://cloudflare-dns.com/dns-query", "cloudflare-dns.com"),
]

# Запасные DoH по голому IP: не требуют работающего системного резолвера.
# Заголовок Host обязателен — без него оба сервиса отвечают 403, потому что
# по одному адресу у них живёт несколько сервисов.
DOH_BY_IP = [
    ("https://1.1.1.1/dns-query", "cloudflare-dns.com", "1.1.1.1 (DoH по IP)"),
    ("https://8.8.8.8/resolve", "dns.google", "8.8.8.8 (DoH по IP)"),
]

DOT_ENDPOINTS = [("1.1.1.1", "Cloudflare DoT"), ("8.8.8.8", "Google DoT")]

FALLBACK_IPS = ["142.250.185.78", "142.250.74.78", "172.217.16.78",
                "216.58.209.174", "142.251.36.14"]

RESULT = {"version": VERSION}


# ==========================================================================
# Вывод
# ==========================================================================

def section(title):
    ttl = re.sub(r"[\r\n]+", " ", str(title))[:66]
    print("\n" + "=" * 66)
    print(ttl)
    print("=" * 66)


def line(k, v):
    """Одна строка отчёта.

    Значения могут прийти из чужого файла, поэтому длина и переводы
    строк ограничиваются здесь, а не в каждом вызове: иначе одно
    поле-переросток разносит вёрстку всего отчёта.
    """
    key = re.sub(r"\s+", " ", str(k))[:36]
    val = re.sub(r"[\r\n]+", " ", str(v))
    if len(val) > 88:
        val = val[:85] + "..."
    print("  {:<36} {}".format(key + ":", val))


def sub(text):
    txt = re.sub(r"[\r\n]+", " ", str(text))
    print("    " + (txt[:96] + "..." if len(txt) > 99 else txt))


def run(cmd):
    """Выполнить команду, вернуть stdout или None."""
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=15, check=False)
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return None


# ==========================================================================
# DNS: провод
# ==========================================================================

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
          3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def build_query(name, qtype=1, dnssec=False, bufsize=0):
    tid = random.randint(0, 0xFFFF)
    arcount = 1 if bufsize else 0
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, arcount)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in name.split(".") if p) + b"\x00"
    pkt = header + qname + struct.pack(">HH", qtype, 1)
    if bufsize:
        # OPT-запись EDNS0: имя = корень, тип 41, класс = размер буфера.
        flags = 0x8000 if dnssec else 0
        pkt += b"\x00" + struct.pack(">HHHHH", 41, bufsize, 0, flags, 0)
    return tid, pkt


def skip_name(buf, off):
    while True:
        if off >= len(buf):
            raise ValueError("обрезанный ответ")
        ln = buf[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2
        off += 1 + ln


def parse_response(buf, tid, strict=True):
    if len(buf) < 12:
        raise ValueError("слишком короткий ответ")
    rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if strict and rid != tid:
        raise ValueError("не совпал transaction id — подмена ответа")
    rcode = RCODES.get(flags & 0x0F, str(flags & 0x0F))
    truncated = bool(flags & 0x0200)
    authentic = bool(flags & 0x0020)      # AD: резолвер проверил подписи
    off = 12
    for _ in range(qd):
        off = skip_name(buf, off) + 4
    ips = []
    ttls = []
    for _ in range(an):
        try:
            off = skip_name(buf, off)
            rtype, _, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        except Exception:
            break
        off += 10
        if rtype in (1, 28):
            ttls.append(ttl)
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in buf[off:off + 4]))
        elif rtype == 28 and rdlen == 16:
            ips.append(socket.inet_ntop(socket.AF_INET6, buf[off:off + 16]))
        off += rdlen
    return {"rcode": rcode, "ips": ips, "truncated": truncated,
            "authentic": authentic, "ttls": ttls, "size": len(buf)}


def dns_udp(server, name, qtype=1, timeout=TIMEOUT, dnssec=False, bufsize=0,
            watch_race=True):
    """DNS по UDP с обнаружением инъекции.

    Подменяющий узел обязан ОПЕРЕДИТЬ настоящий резолвер, поэтому первым
    приходит подделка, а следом — честный ответ. Обычный резолвер взял бы
    первый и не заметил ничего. Мы после первого ответа ещё немного слушаем
    сокет: второй ответ с тем же id, но другими адресами — прямая улика
    подмены на транзите.

    Также фиксируем пакеты с чужим transaction id — это слепая инъекция.
    """
    tid, pkt = build_query(name, qtype, dnssec, bufsize)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    wrong_id = 0
    try:
        s.sendto(pkt, (server, 53))
        first = None
        deadline = t0 + timeout
        while True:
            try:
                buf, _ = s.recvfrom(65535)
            except socket.timeout:
                break
            try:
                parsed = parse_response(buf, tid)
            except ValueError:
                wrong_id += 1
                if time.time() >= deadline:
                    break
                s.settimeout(max(0.1, deadline - time.time()))
                continue
            first = parsed
            break
        if first is None:
            if wrong_id:
                return {"ok": False, "error": "ответы с чужим id ({})".format(wrong_id),
                        "wrong_id": wrong_id}
            return {"ok": False, "error": "timeout",
                    "hint": "пакет не дошёл или отброшен"}

        first["ok"] = True
        first["ms"] = int((time.time() - t0) * 1000)
        if wrong_id:
            first["wrong_id"] = wrong_id

        # Короткое дослушивание: гонка ответов = инъекция.
        # Критерий строгий, чтобы не спутать с обычной ротацией адресов у
        # честного резолвера: наборы должны НЕ ПЕРЕСЕКАТЬСЯ, либо второй
        # пакет должен прийти с чужого адреса.
        if watch_race and qtype == 1:
            s.settimeout(0.7)
            try:
                buf2, addr2 = s.recvfrom(65535)
                second = parse_response(buf2, tid)
                a = set(first.get("ips") or [])
                b = set(second.get("ips") or [])
                foreign = bool(addr2 and addr2[0] != server)
                # Честная ротация остаётся в тех же сетях (у Google это
                # 142.250.x / 172.217.x). Подделка уводит в чужую сеть —
                # только это и считаем инъекцией.
                if b and a and (not _same_nets(a, b) or foreign):
                    first["race"] = {"first": sorted(a), "second": sorted(b),
                                     "foreign_src": addr2[0] if foreign else None}
            except Exception:
                pass
        return first
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        s.close()


def dns_tcp(server, name, qtype=1, timeout=TIMEOUT):
    """DNS поверх TCP:53. Иногда UDP режут, а TCP забывают."""
    tid, pkt = build_query(name, qtype)
    framed = struct.pack(">H", len(pkt)) + pkt
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((server, 53))
        s.sendall(framed)
        head = s.recv(2)
        if len(head) < 2:
            return {"ok": False, "error": "соединение закрыто без ответа"}
        need = struct.unpack(">H", head)[0]
        buf = b""
        while len(buf) < need:
            chunk = s.recv(need - len(buf))
            if not chunk:
                break
            buf += chunk
        r = parse_response(buf, tid)
        r["ok"] = True
        r["ms"] = int((time.time() - t0) * 1000)
        return r
    except socket.timeout:
        return {"ok": False, "error": "timeout"}
    except ConnectionResetError:
        return {"ok": False, "error": "RST — соединение сброшено"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        s.close()


def doh_query(url, name, by_ip=False, host=None):
    """DNS-over-HTTPS. by_ip=True — обращение к резолверу по голому IP.

    В этом режиме имя в сертификате не совпадёт с IP, поэтому проверка
    имени отключается. Для диагностики это допустимо: нас интересует
    сам факт прохождения запроса, а не доверие к сертификату.
    """
    headers = {"Accept": "application/dns-json", "User-Agent": "netprobe/3"}
    if host:
        # Без правильного Host сервис не поймёт, к какому из своих
        # приложений обращаются, и вернёт 403.
        headers["Host"] = host
    req = urllib.request.Request(
        "{}?name={}&type=A".format(url, name), headers=headers)
    t0 = time.time()
    try:
        if by_ip:
            # Сертификат выписан на имя, а мы идём по IP — проверку имени
            # снимаем осознанно: нас интересует проходимость, не доверие.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ctx))
            resp = opener.open(req, timeout=TIMEOUT)
        else:
            resp = urllib.request.urlopen(req, timeout=TIMEOUT)
        with resp as r:
            data = json.loads(r.read().decode("utf-8"))
        ips = [a.get("data") for a in data.get("Answer", []) if a.get("type") == 1]
        return {"ok": True, "rcode": RCODES.get(data.get("Status", 0), "?"),
                "ips": ips, "ms": int((time.time() - t0) * 1000)}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def dot_probe(ip, timeout=TIMEOUT):
    """Доступен ли DNS-over-TLS (TCP:853). Проверяем сам факт handshake."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, 853))
        w = ctx.wrap_socket(s)
        w.close()
        return {"ok": True}
    except socket.timeout:
        return {"ok": False, "error": "timeout"}
    except ConnectionResetError:
        return {"ok": False, "error": "RST"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    finally:
        try:
            s.close()
        except Exception:
            pass


def nxdomain_hijack(server):
    """Отдаёт ли резолвер адрес на заведомо несуществующее имя.

    Честный резолвер обязан ответить NXDOMAIN. Если вместо этого приходит
    IP — провайдер перехватывает несуществующие домены и уводит их на свою
    страницу. Побочный эффект: перестают работать внутренние имена и
    ломается определение «сайт не существует».
    """
    rnd = "netprobe-{}-{}.invalid".format(random.randint(10 ** 6, 10 ** 7),
                                          int(time.time()) % 10000)
    r = dns_udp(server, rnd, timeout=4, watch_race=False)
    if not r.get("ok"):
        return {"ok": False, "error": r.get("error")}
    return {"ok": True, "rcode": r.get("rcode"), "ips": r.get("ips") or [],
            "hijacked": bool(r.get("ips"))}


def dnssec_check(server):
    """Проверяет ли резолвер подписи DNSSEC.

    Запрашиваем подписанный домен с DO-битом и смотрим флаг AD. Без
    валидации подменённый ответ невозможно отличить от настоящего
    средствами самого DNS.
    """
    good = dns_udp(server, "cloudflare.com", dnssec=True, bufsize=1232,
                   timeout=4, watch_race=False)
    if not good.get("ok"):
        return {"ok": False, "error": good.get("error")}
    return {"ok": True, "validates": bool(good.get("authentic")),
            "rcode": good.get("rcode")}


def cross_check(plain, doh):
    """Сравнение ответов по открытому :53 и по DoH для одного имени.

    Самая прямая улика манипуляции: DoH подделать нельзя, поэтому
    непересекающиеся наборы адресов означают, что открытый 53 врёт.
    """
    a = set((plain or {}).get("ips") or [])
    b = set((doh or {}).get("ips") or [])
    if not a or not b:
        return {"ok": False, "error": "нет пары для сравнения"}
    # У Google анкаст: полного совпадения не будет, но подсеть /16 совпадает.
    def net16(ips):
        return {".".join(i.split(".")[:2]) for i in ips if ":" not in i}
    same_net = bool(net16(a) & net16(b))
    return {"ok": True, "match": bool(a & b), "same_network": same_net,
            "plain": sorted(a)[:3], "doh": sorted(b)[:3],
            "suspicious": not same_net}


def http_blockpage(host="youtube.com", timeout=TIMEOUT):
    """Не подсовывает ли провайдер страницу-заглушку по HTTP.

    Блокировки часто ставят на 80-й порт редирект на свою страницу.
    Смотрим код ответа, куда ведёт Location и есть ли типовые маркеры.
    """
    markers = ("ограничен", "заблокирован", "запрещен", "реестр",
               "roskomnadzor", "rkn.gov", "blocked", "eais")
    try:
        req = urllib.request.Request("http://{}/".format(host),
                                     headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(4096).decode("utf-8", "replace").lower()
            final = r.geturl()
            hit = [m for m in markers if m in body or m in final.lower()]
            return {"ok": True, "code": r.getcode(), "final_url": final,
                    "markers": hit, "blockpage": bool(hit)}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__ + ": " + str(e)[:50]}


def system_resolve(name, family=socket.AF_INET):
    try:
        infos = socket.getaddrinfo(name, 443, family, socket.SOCK_STREAM)
        return {"ok": True, "ips": sorted({i[4][0] for i in infos})}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def classify(res):
    """Свести результат запроса к одному внятному статусу.

    Возвращает (код, подпись). Коды используются и в выводе, и в сравнении,
    поэтому формулировки одинаковы везде.
    """
    if res is None:
        return "n/a", "не проверялось"
    if not res.get("ok"):
        err = str(res.get("error", "")).lower()
        if "timeout" in err:
            return "silent", "молчит (пакет отброшен)"
        if "temporary failure in name res" in err or "errno -3" in err:
            return "resolver_down", "системный резолвер недоступен"
        if "name or service not known" in err or "errno -2" in err:
            return "nxdomain_sys", "имя не разрешается системой"
        if "not permitted" in err or "errno 1]" in err or "errno 13]" in err:
            return "blocked_local", "запрещено локально (файрвол/kill switch)"
        if "refused" in err or "errno 111" in err:
            return "refused", "отклонено (порт закрыт или локальный запрет)"
        if "unreachable" in err or "network is unreachable" in err:
            return "noroute", "нет маршрута"
        if "rst" in err or "reset" in err:
            return "rst", "сброс соединения"
        if "transaction id" in err:
            return "forged", "ПОДМЕНА (чужой ответ)"
        return "fail", "ошибка — " + str(res.get("error", "?"))[:40]
    if res.get("race"):
        return "injected", "ИНЪЕКЦИЯ (пришло два разных ответа)"
    if res.get("suspect"):
        return "forged", "ПОДМЕНА (ответ подделан)"
    if not res.get("ips"):
        return "empty", "не резолвит ({}, пустой ответ)".format(res.get("rcode", "?"))
    return "resolves", "резолвит"


def fmt(res):
    code, label = classify(res)
    if code == "resolves":
        ips = res.get("ips") or []
        tail = "" if len(ips) <= 3 else " (+{})".format(len(ips) - 3)
        return "резолвит — {}{}".format(", ".join(ips[:3]), tail)
    if code == "injected":
        rc = res["race"]
        extra = (", второй пакет с чужого адреса " + rc["foreign_src"]
                 if rc.get("foreign_src") else "")
        return "{}: сначала {} потом {}{}".format(
            label, ", ".join((rc.get("first") or [])[:2]),
            ", ".join((rc.get("second") or [])[:2]), extra)
    if code == "forged" and res.get("ips"):
        return "{} — {}".format(label, ", ".join(res["ips"][:2]))
    return label


def mark_suspect(data, blackhole):
    """Пометить как подделанные все ответы по открытому UDP:53.

    Если резолвер, которого не существует, что-то ответил, значит порт 53
    перехватывается целиком. Тогда ЛЮБОЙ ответ по открытому 53 недостоверен,
    каким бы адресом ты его ни адресовал. DoH и DoT это не касается.
    """
    if not blackhole.get("ok"):
        return 0
    fake_ips = set(blackhole.get("ips") or [])
    n = 0
    for res in (data.get("resolvers") or {}).values():
        for r in res.values():
            if r.get("ok"):
                r["suspect"] = True
                r["suspect_reason"] = ("совпал с ответом из пустоты"
                                       if set(r.get("ips") or []) & fake_ips
                                       else "перехват порта 53")
                n += 1
    return n


# ==========================================================================
# Транспорт: TCP, TLS/SNI, QUIC
# ==========================================================================

def tcp_probe(ip, port=443, timeout=TIMEOUT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
        return {"ok": True, "ms": int((time.time() - t0) * 1000)}
    except socket.timeout:
        return {"ok": False, "error": "timeout"}
    except ConnectionRefusedError:
        return {"ok": False, "error": "refused"}
    except ConnectionResetError:
        return {"ok": False, "error": "RST"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    finally:
        s.close()


def tls_probe(ip, sni, port=443, timeout=TIMEOUT):
    """TLS-handshake на конкретный IP с подставленным именем.

    Классификация важнее факта успеха:
      ok      — рукопожатие прошло, имя не режется
      rst     — сброс после ClientHello: активный DPI по SNI
      timeout — молчание после ClientHello: тихий drop по SNI
      refused — порт закрыт (это уже не про SNI)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
    except Exception as e:
        s.close()
        return {"ok": False, "stage": "tcp", "verdict": "tcp-fail",
                "error": "TCP не открылся ({})".format(type(e).__name__)}
    try:
        w = ctx.wrap_socket(s, server_hostname=sni)
        cipher = w.cipher()
        cert_cn = ""
        try:
            der = w.getpeercert(binary_form=True)
            cert_cn = "cert:{}B".format(len(der)) if der else ""
        except Exception:
            pass
        w.close()
        return {"ok": True, "stage": "tls", "verdict": "ok",
                "proto": cipher[1] if cipher else "?", "note": cert_cn,
                "ms": int((time.time() - t0) * 1000)}
    except ConnectionResetError:
        return {"ok": False, "stage": "tls", "verdict": "rst",
                "error": "RST после ClientHello"}
    except socket.timeout:
        return {"ok": False, "stage": "tls", "verdict": "timeout",
                "error": "молчание после ClientHello"}
    except ssl.SSLError as e:
        return {"ok": False, "stage": "tls", "verdict": "tls-error",
                "error": str(e).split("(")[0][:60]}
    except Exception as e:
        return {"ok": False, "stage": "tls", "verdict": "other",
                "error": type(e).__name__}
    finally:
        try:
            s.close()
        except Exception:
            pass


KNOWN_CAS = ("Google Trust Services", "GTS CA", "GTS Root", "DigiCert",
             "Let's Encrypt", "Cloudflare", "Amazon", "Sectigo",
             "GlobalSign", "ISRG", "Baltimore")


def cert_info(ip, sni, port=443, timeout=TIMEOUT):
    """Кто на самом деле выдал сертификат на том конце.

    Если провайдер, корпоративный шлюз или антивирус вклинивается в HTTPS,
    сертификат будет подписан их собственным центром, а не публичным.
    Соединение при этом выглядит рабочим, но содержимое читается третьей
    стороной. Валидацию отключаем намеренно: нужен сам сертификат, а не
    вердикт системы о доверии.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        w = ctx.wrap_socket(s, server_hostname=sni)
        der = w.getpeercert(binary_form=True)
        w.close()
        if not der:
            return {"ok": False, "error": "сертификат не получен"}
        # Разбор без внешних библиотек: печатаемые строки из DER.
        chunks = re.findall(r"[ -~]{4,}", der.decode("latin-1"))
        issuer = ""
        for known in KNOWN_CAS:
            if any(known in c for c in chunks):
                issuer = known
                break
        return {"ok": True, "issuer": issuer, "size": len(der),
                "known_ca": bool(issuer),
                "strings": [c for c in chunks if len(c) < 60][:8]}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    finally:
        try:
            s.close()
        except Exception:
            pass


def port_matrix(ip, timeout=3):
    """Какие транспорты доживают до узла.

    Когда 443 режут, важно знать, остались ли пути через 80, 853 или
    нестандартные порты — на них можно переставить точку входа.
    """
    out = {}
    for port, what in [(80, "HTTP"), (443, "HTTPS"), (853, "DoT"),
                       (8443, "HTTPS альт."), (2053, "Cloudflare альт.")]:
        out["{} ({})".format(port, what)] = tcp_probe(ip, port, timeout=timeout)
    return out


def path_mtu(dst):
    """Оценка path MTU: UDP с запретом фрагментации, размер сверху вниз.

    Завышенный MTU туннеля даёт узнаваемую картину: короткие запросы
    ходят, а страницы виснут на середине. Linux-only.
    """
    if platform.system() != "Linux":
        return {"ok": False, "error": "поддерживается только на Linux"}
    # Python не во всех сборках экспортирует эти константы, хотя ядро их
    # понимает. Числа фиксированы в заголовках Linux: IP_MTU_DISCOVER=10,
    # IP_PMTUDISC_DO=2. Берём из модуля, если есть, иначе напрямую.
    opt = getattr(socket, "IP_MTU_DISCOVER", 10)
    do = getattr(socket, "IP_PMTUDISC_DO", 2)
    for size in (1500, 1472, 1420, 1380, 1280, 1200):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.setsockopt(socket.IPPROTO_IP, opt, do)
            s.settimeout(2)
            s.sendto(b"\x00" * max(0, size - 28), (dst, 33434))
            return {"ok": True, "mtu": size}
        except OSError:
            continue
        finally:
            s.close()
    return {"ok": False, "error": "не прошёл даже 1200 байт"}


def quic_probe(ip, port=443, timeout=TIMEOUT):
    """Проверка UDP:443 (QUIC) через Version Negotiation.

    Шлём пакет с заведомо несуществующей версией. Живой QUIC-сервер обязан
    ответить Version Negotiation (version == 0). Это отличает
    'UDP:443 режут' от 'сервер не отвечает'. YouTube без QUIC работает
    заметно хуже, а иногда именно QUIC и режут точечно.
    """
    dcid = bytes(random.getrandbits(8) for _ in range(8))
    scid = bytes(random.getrandbits(8) for _ in range(8))
    pkt = b"\xc3" + b"\x0a\x0a\x0a\x0a"          # long header + reserved version
    pkt += bytes([len(dcid)]) + dcid
    pkt += bytes([len(scid)]) + scid
    pkt += b"\x00" * (1200 - len(pkt))           # QUIC требует >= 1200 байт
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.sendto(pkt, (ip, port))
        buf, _ = s.recvfrom(2048)
        if len(buf) >= 5 and (buf[0] & 0x80) and buf[1:5] == b"\x00\x00\x00\x00":
            return {"ok": True, "verdict": "version-negotiation",
                    "ms": int((time.time() - t0) * 1000)}
        return {"ok": True, "verdict": "ответ есть, но не VN",
                "ms": int((time.time() - t0) * 1000)}
    except socket.timeout:
        return {"ok": False, "error": "timeout — UDP:443 не проходит"}
    except Exception as e:
        return {"ok": False, "error": type(e).__name__}
    finally:
        s.close()


# ==========================================================================
# Маршрутизация и интерфейсы
# ==========================================================================

TUNNEL_HINTS = ("wg", "awg", "amn", "tun", "tap", "vpn", "nekoray", "proton",
                "utun", "wintun", "wireguard", "openvpn", "zerotier",
                "tailscale", "hamachi", "outline", "warp", "forti")


def src_ip_for(dst, port=53, udp=True, family=socket.AF_INET):
    """Какой локальный адрес ядро выберет для отправки на dst.

    connect() на UDP не шлёт ни байта — только выбирает маршрут.
    Именно это показывает, идёт трафик в туннель или мимо."""
    try:
        s = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    except OSError:
        return None          # семейство адресов не поддержано (нет IPv6-стека)
    s.settimeout(2)
    try:
        s.connect((dst, port))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()


def local_interfaces():
    """Список (имя, адрес) по системным утилитам. Best effort."""
    out = []
    if platform.system() == "Windows":
        txt = run("ipconfig") or ""
        cur = None
        for ln in txt.splitlines():
            m = re.match(r"^[A-Za-zА-Яа-я].*?[:：]\s*$", ln)
            if m:
                cur = ln.strip().rstrip(":")
            m2 = re.search(r"IPv4.*?[:：]\s*([0-9.]+)", ln)
            if m2 and cur:
                out.append((cur, m2.group(1)))
    else:
        txt = run("ip -o -4 addr show") or ""
        for ln in txt.splitlines():
            parts = ln.split()
            if len(parts) >= 4:
                out.append((parts[1], parts[3].split("/")[0]))
    return out


def looks_like_tunnel(name):
    n = (name or "").lower()
    return any(h in n for h in TUNNEL_HINTS)


def routing_report(dns_addr):
    section("1. МАРШРУТИЗАЦИЯ — куда уходит трафик")
    ifaces = local_interfaces()
    tun = [(n, a) for n, a in ifaces if looks_like_tunnel(n)]
    # Termux и урезанные системы не дают перечислить интерфейсы. Отсутствие
    # списка НЕ означает отсутствия туннеля — это отсутствие данных, и
    # выводы о утечке по нему делать нельзя.
    known = bool(ifaces)

    for n, a in ifaces:
        mark = "  <- туннель" if looks_like_tunnel(n) else ""
        sub("{:<32} {}{}".format(n[:32], a, mark))
    if not known:
        sub("Перечислить интерфейсы не удалось (нет ip/ipconfig).")

    print()
    src_web = src_ip_for("8.8.8.8", 443, udp=False)
    src_dns = src_ip_for("8.8.8.8", 53, udp=True)
    src_local = src_ip_for(dns_addr, 53, udp=True) if dns_addr else None

    line("исходящий адрес для HTTPS", src_web or "не определён")
    line("исходящий адрес для DNS", src_dns or "не определён")
    if dns_addr:
        line("исходящий адрес до {}".format(dns_addr), src_local or "маршрута нет")

    tun_addrs = {a for _, a in tun}
    if known and tun:
        dns_in_tunnel = bool(src_dns and src_dns in tun_addrs)
        web_in_tunnel = bool(src_web and src_web in tun_addrs)
    elif known:
        dns_in_tunnel = web_in_tunnel = False
    else:
        dns_in_tunnel = web_in_tunnel = None      # неизвестно, не False

    print()
    if not known:
        sub("Идёт ли трафик через туннель — определить нельзя.")
        sub("Косвенно: если исходящий адрес выше из диапазона 10.x/172.16-31.x")
        sub("и отличается от адреса домашней сети, туннель, скорее всего, поднят.")
    elif not tun:
        sub("Туннельных интерфейсов не найдено — прогон, похоже, без VPN.")
    else:
        line("HTTPS идёт через туннель", "ДА" if web_in_tunnel else "НЕТ")
        line("DNS идёт через туннель", "ДА" if dns_in_tunnel else "НЕТ  <-- утечка")

    # IPv6: частая тихая утечка мимо IPv4-туннеля
    src6 = src_ip_for("2001:4860:4860::8888", 443, udp=False, family=socket.AF_INET6)
    line("IPv6 наружу", src6 if src6 else "нет (это хорошо при IPv4-туннеле)")

    RESULT["routing"] = {
        "ifaces": ifaces, "tunnels": tun, "ifaces_known": known,
        "src_web": src_web, "src_dns": src_dns, "src_local": src_local,
        "dns_in_tunnel": dns_in_tunnel, "web_in_tunnel": web_in_tunnel,
        "ipv6": src6,
    }
    return dns_in_tunnel, web_in_tunnel, (bool(tun) if known else None)


def android_private_dns():
    """Состояние «Частного DNS» на Android.

    Это отдельный канал резолва (DoT), который система держит МИМО
    VPN-туннеля. Именно он чаще всего и оставляет Android без резолва
    при поднятом VPN. Работает только там, где доступна утилита settings
    (Termux); на прочих системах возвращает None.
    """
    if not (os.path.exists("/system/build.prop") or "ANDROID_ROOT" in os.environ):
        return None
    mode = run("settings get global private_dns_mode 2>/dev/null")
    host = run("settings get global private_dns_specifier 2>/dev/null")
    if not mode:
        return None
    mode = mode.strip()
    host = (host or "").strip()
    return {"mode": mode, "host": host if host and host != "null" else ""}


def system_resolvers():
    """Какие резолверы реально настроены в системе."""
    found = []
    if platform.system() == "Windows":
        txt = run("ipconfig /all") or ""
        # Windows печатает второй и последующие DNS-серверы отдельными
        # строками без подписи — их надо добирать, пока идут одни адреса.
        in_dns = False
        for ln in txt.splitlines():
            m = re.search(r"DNS[^\n]*?[:：]\s*([0-9a-fA-F.:]+)\s*$", ln)
            if m:
                found.append(m.group(1))
                in_dns = True
                continue
            if in_dns:
                m2 = re.match(r"^\s{6,}([0-9a-fA-F.:]+)\s*$", ln)
                if m2:
                    found.append(m2.group(1))
                else:
                    in_dns = False
    else:
        txt = run("resolvectl status") or ""
        if txt:
            cur_link = None
            for ln in txt.splitlines():
                lm = re.match(r"Link \d+ \((\S+)\)", ln.strip())
                if lm:
                    cur_link = lm.group(1)
                m = re.search(r"Current DNS Server:\s*(\S+)", ln)
                if m:
                    found.append("{} ({})".format(m.group(1), cur_link or "?"))
                m2 = re.search(r"DNS Domain:\s*~\.", ln)
                if m2 and found:
                    found[-1] += " [~. — все имена сюда]"
        if not found:
            try:
                with open("/etc/resolv.conf", encoding="utf-8") as f:
                    for ln in f:
                        if ln.startswith("nameserver"):
                            found.append(ln.split()[1])
            except Exception:
                pass
    seen, uniq = set(), []
    for f in found:
        if f not in seen:
            seen.add(f)
            uniq.append(f)
    return uniq


# ==========================================================================
# Клиентский режим
# ==========================================================================

def dns_report(dns_addr):
    section("2. DNS — кто отвечает и что именно")

    sysres = system_resolvers()
    line("резолверы в системе", ", ".join(sysres) if sysres else "не определены")

    pdns = android_private_dns()
    if pdns:
        m = pdns["mode"]
        label = {"off": "выключен (правильно)",
                 "opportunistic": "автоматический",
                 "hostname": "включён вручную"}.get(m, m)
        line("Частный DNS (Android)",
             label + (": " + pdns["host"] if pdns["host"] else ""))
        if m != "off":
            sub("Это отдельный канал резолва мимо VPN-туннеля. На время")
            sub("диагностики выключи: Настройки -> Сеть -> Частный DNS.")
        RESULT.setdefault("android", {})["private_dns"] = pdns

    stub = any(s.startswith("127.0.0.5") for s in sysres)
    if stub:
        sub("127.0.0.53 — это заглушка systemd-resolved, не настоящий апстрим.")
        sub("Смотри строку Current DNS Server у нужного интерфейса выше.")

    data = {"system": {}, "resolvers": {}, "doh": {}, "tcp53": {}}

    # Сначала проверяем, можно ли вообще верить ответам по открытому :53.
    print("\n  -- достоверность порта 53 --")
    bh = {"ok": False, "error": "timeout"}
    answered = []
    for addr in BLACKHOLE_RESOLVERS:
        r = dns_udp(addr, "www.youtube.com", timeout=3)
        data.setdefault("blackhole_all", {})[addr] = r
        if r.get("ok"):
            answered.append(addr)
            if not bh.get("ok"):
                bh = r
    data["blackhole"] = bh
    intercepted = bool(answered)
    if intercepted:
        line("запрос в пустоту ({} адресов)".format(len(BLACKHOLE_RESOLVERS)),
             "ОТВЕТИЛИ: " + ", ".join(answered) + "  <-- перехват")
        sub("Резолверов по этим адресам не существует. Значит порт 53")
        sub("перехватывается, и ЛЮБОЙ ответ по нему недостоверен.")
        if bh.get("ips"):
            sub("Подставленные адреса: " + ", ".join(bh["ips"][:3]))
    else:
        line("запрос в пустоту ({} адресов)".format(len(BLACKHOLE_RESOLVERS)),
             "все молчат — перехвата нет (норма)")

    print("\n  -- системный резолвер --")
    for d in YT_DOMAINS[:3] + CONTROL_DOMAINS[:1]:
        r = system_resolve(d)
        data["system"][d] = r
        line(d, fmt(r))

    if dns_addr:
        print("\n  -- {} (резолвер в туннеле) --".format(dns_addr))
        for d in YT_DOMAINS[:3]:
            r = dns_udp(dns_addr, d)
            data["resolvers"].setdefault(dns_addr, {})[d] = r
            line(d, fmt(r))

    for ip, name in PUBLIC_RESOLVERS:
        print("\n  -- {} ({}) --".format(ip, name))
        for n_dom, d in enumerate(YT_DOMAINS[:2]):
            # Если резолвер уже промолчал на первом имени, второе даст ровно
            # тот же таймаут. Не тратим на это ещё пять секунд — в сети с
            # блокировками такие ожидания складываются в минуты.
            prev = data["resolvers"].get(ip, {}).get(YT_DOMAINS[0])
            if n_dom and prev is not None and classify(prev)[0] in (
                    "silent", "blocked_local", "noroute"):
                data["resolvers"][ip][d] = dict(prev, skipped=True)
                line(d, classify(prev)[1] + " (не перепроверялось)")
                continue
            r = dns_udp(ip, d)
            data["resolvers"].setdefault(ip, {})[d] = r
            line(d, fmt(r))

    # Гонка ответов — независимая улика подмены, даже если проба в пустоту
    # промолчала (её могли отбросить отдельным правилом).
    injected = [(srv, d) for srv, res in data["resolvers"].items()
                for d, r in res.items() if r.get("race")]
    if injected:
        print()
        sub("Обнаружена ИНЪЕКЦИЯ DNS: на один запрос пришло два разных")
        sub("ответа. Подставной опередил настоящий — так работает подмена")
        sub("на транзите. Затронуты: " +
            ", ".join("{} @ {}".format(d, srv) for srv, d in injected[:3]))
        data["injected"] = [{"resolver": srv, "domain": d} for srv, d in injected]

    n = mark_suspect(data, bh)
    if n:
        print()
        sub("Ответов помечено как недостоверные: {}.".format(n))
        sub("Они выглядят успешными, но пришли от перехватчика, а не от")
        sub("указанного резолвера. Как успех НЕ засчитываются.")
        # перерисовываем строки с учётом подмены
        print("\n  -- те же ответы с поправкой на перехват --")
        for srv, res in data["resolvers"].items():
            for d, r in res.items():
                if r.get("suspect"):
                    line("{} @ {}".format(d, srv), fmt(r))

    print("\n  -- качество резолвера --")
    probe_srv = dns_addr or PUBLIC_RESOLVERS[0][0]
    nx = nxdomain_hijack(probe_srv)
    data["nxdomain"] = nx
    if nx.get("ok"):
        if nx.get("hijacked"):
            line("несуществующее имя", "ОТДАН АДРЕС: " + ", ".join(nx["ips"][:2]))
            sub("Резолвер обязан ответить NXDOMAIN. Вместо этого уводит на")
            sub("свою страницу — перехват несуществующих доменов.")
        else:
            line("несуществующее имя", "{} (правильно)".format(nx.get("rcode")))
    else:
        line("несуществующее имя", classify(nx)[1])

    ds = dnssec_check(probe_srv)
    data["dnssec"] = ds
    if ds.get("ok"):
        line("проверка подписей DNSSEC",
             "выполняется" if ds.get("validates") else "НЕ выполняется")
        if not ds.get("validates"):
            sub("Без валидации подменённый ответ средствами DNS не отличить")
            sub("от настоящего. У рекурсивного unbound её стоит включить.")
    else:
        line("проверка подписей DNSSEC", classify(ds)[1])

    print("\n  -- прочие проверки транспорта DNS --")

    t53 = dns_tcp("8.8.8.8", "www.youtube.com")
    data["tcp53"]["8.8.8.8"] = t53
    line("DNS поверх TCP:53 -> 8.8.8.8", fmt(t53))

    # Большой ответ с DNSSEC — ловит блэкхол по фрагментации/MTU.
    # Вывод про MTU имеет смысл только если КОРОТКИЕ запросы к тому же
    # резолверу проходят. Иначе это просто общий запрет на :53.
    small = dns_udp("8.8.8.8", "www.google.com")
    big = dns_udp("8.8.8.8", ".", qtype=48, dnssec=True, bufsize=4096)
    data["big_udp"] = big
    data["small_udp"] = small
    if big.get("ok"):
        line("большой UDP-ответ (DNSKEY)", "{} байт — проходит".format(big.get("size")))
    elif small.get("ok"):
        line("большой UDP-ответ (DNSKEY)", classify(big)[1])
        sub("Короткие ответы проходят, длинные нет — похоже на MTU/фрагментацию.")
    else:
        line("большой UDP-ответ (DNSKEY)", classify(big)[1])
        sub("Короткие запросы к 8.8.8.8 тоже не проходят — дело не в MTU,")
        sub("а в общем запрете на порт 53. Для MTU вывода данных нет.")


    print("\n  -- шифрованный DNS (перехвату не подвержен) --")
    for url, name in DOH_ENDPOINTS:
        r = doh_query(url, "www.youtube.com")
        data["doh"][name] = r
        line("DoH " + name, fmt(r))
    if not any(r.get("ok") for r in data["doh"].values()):
        sub("DoH по имени не сработал — вероятно, сломан системный резолвер.")
        sub("Пробуем те же сервисы по голому IP, без участия DNS:")
        for url, host, name in DOH_BY_IP:
            r = doh_query(url, "www.youtube.com", by_ip=True, host=host)
            data["doh"][name] = r
            line("DoH " + name, fmt(r))
    for ip, name in DOT_ENDPOINTS:
        r = dot_probe(ip)
        data.setdefault("dot", {})[name] = r
        line("DoT " + name,
             "доступен" if r.get("ok") else "недоступен — " + str(r.get("error")))

    # Сверка транспортов: DoH подделать нельзя, поэтому расхождение
    # адресов между ним и открытым :53 — прямая улика манипуляции.
    doh_ref = next((r for r in data["doh"].values()
                    if r.get("ok") and r.get("ips")), None)
    plain_ref = None
    for srv in ([dns_addr] if dns_addr else []) + [x[0] for x in PUBLIC_RESOLVERS]:
        cand = (data["resolvers"].get(srv) or {}).get("www.youtube.com")
        if cand and cand.get("ok") and cand.get("ips"):
            plain_ref = cand
            break
    if doh_ref and plain_ref:
        xc = cross_check(plain_ref, doh_ref)
        data["cross_check"] = xc
        print()
        if xc.get("suspicious"):
            line("сверка :53 против DoH", "РАСХОЖДЕНИЕ")
            sub("По открытому 53: " + ", ".join(xc["plain"]))
            sub("По DoH:           " + ", ".join(xc["doh"]))
            sub("Разные сети — открытый 53 отдаёт не те адреса.")
        else:
            line("сверка :53 против DoH",
                 "совпадает" if xc.get("match") else "та же сеть (норма для анкаста)")

    data["intercepted"] = bool(intercepted)
    RESULT["dns"] = data
    return data


def pick_ip(data):
    """Взять достоверный IP Google для проверок транспорта.

    Подделанные ответы игнорируем: тестировать TLS против адреса
    заглушки провайдера бессмысленно и даёт ложный вывод.
    Приоритет: DoH (перехвату не подвержен) -> система -> резолверы.
    """
    def v4(rec):
        """Первый пригодный IPv4 из записи, если она вообще словарь."""
        if not isinstance(rec, dict) or not rec.get("ok"):
            return None
        for ip in dlist(rec, "ips"):
            if isinstance(ip, str) and ":" not in ip and re.match(
                    r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                return ip
        return None

    for r in dget(data, "doh").values():
        ip = v4(r)
        if ip:
            return ip, "DoH"
    if not (isinstance(data, dict) and data.get("intercepted")):
        for d, r in dget(data, "system").items():
            ip = v4(r)
            if ip:
                return ip, d
        for srv, res in dget(data, "resolvers").items():
            if not isinstance(res, dict):
                continue
            for d, r in res.items():
                if isinstance(r, dict) and not r.get("suspect"):
                    ip = v4(r)
                    if ip:
                        return ip, "{} @ {}".format(d, srv)
    return FALLBACK_IPS[0], "запасной список"


def verified_ip(data):
    """Выбрать тестовый IP и убедиться, что он вообще живой.

    Если адрес взят из запасного списка, он мог протухнуть: у Google анкаст
    и постоянная ротация адресов. Проверять блокировки против мёртвого
    адреса — верный способ получить ложный вывод «блок по IP». Поэтому
    запасные адреса перебираются, пока не найдётся отвечающий.
    """
    ip, origin = pick_ip(data)
    if origin != "запасной список":
        return ip, origin, True
    for cand in FALLBACK_IPS:
        if tcp_probe(cand, 443, timeout=3).get("ok"):
            return cand, "запасной список (проверен)", True
    return ip, "запасной список — ни один адрес не ответил", False


def transport_report(data):
    section("3. ТРАНСПОРТ — режется ли по имени, по IP или по протоколу")

    ip, origin, trusted = verified_ip(data)
    line("тестовый IP Google", "{} ({})".format(ip, origin))
    if not trusted:
        sub("Достоверный адрес получить не удалось: DNS сломан, а запасные")
        sub("адреса не отвечают. Выводы этого раздела НЕ надёжны.")

    tcp = tcp_probe(ip, 443)
    line("TCP:443 без TLS", "открыт, {} мс".format(tcp["ms"]) if tcp.get("ok")
         else classify(tcp)[1])
    if not tcp.get("ok"):
        if trusted:
            sub("Порт не открывается вовсе — это блок по IP, до SNI дело не доходит.")
        else:
            sub("Адрес не отвечает, но он и не подтверждён — это может быть")
            sub("просто устаревший IP, а не блокировка. Вывод не делается.")

    print("\n  -- один и тот же IP, разные имена в ClientHello --")
    sni_res = {}
    for sni in ["www.youtube.com", "youtubei.googleapis.com",
                "www.google.com", "example.com"]:
        r = tls_probe(ip, sni)
        sni_res[sni] = r
        if r.get("ok"):
            line(sni, "OK ({}, {} мс)".format(r.get("proto"), r.get("ms")))
        else:
            line(sni, "{} — {}".format(r.get("verdict", "?"), r.get("error")))

    print("\n  -- охват фильтрации: те же условия, разные имена --")
    scope = {}
    if trusted and tcp.get("ok"):
        for sni, label in SCOPE_SNI:
            if sni in sni_res:                       # уже проверено выше
                r = sni_res[sni]
            else:
                r = tls_probe(ip, sni)
            scope[sni] = r
            if r.get("ok"):
                line(label, "проходит")
            else:
                line(label, {"rst": "режется (RST)", "timeout": "режется (drop)",
                             "tcp-fail": "TCP не открылся"}.get(
                                 r.get("verdict"), "не проходит"))
        blocked = [l for sni, l in SCOPE_SNI
                   if not scope.get(sni, {}).get("ok") and "контроль" not in l]
        ctrl_ok = all(scope.get(sni, {}).get("ok")
                      for sni, l in SCOPE_SNI if "контроль" in l)
        print()
        if blocked and ctrl_ok:
            sub("Режется по имени: " + ", ".join(blocked))
            sub("Контрольные имена проходят — значит фильтр именно по SNI,")
            sub("а не общая поломка канала.")
        elif not blocked:
            sub("Ни одно имя не режется — фильтрации по SNI на этом пути нет.")
    else:
        sub("Пропущено: нет достоверного узла для проверки.")

    print("\n  -- сертификат: не вклинился ли кто в HTTPS --")
    cert = cert_info(ip, "www.youtube.com") if tcp.get("ok") else {"ok": False}
    if cert.get("ok"):
        line("удостоверяющий центр",
             cert.get("issuer") or "НЕ ОПОЗНАН  <-- возможна подмена HTTPS")
        line("размер сертификата", "{} байт".format(cert.get("size")))
        if not cert.get("known_ca"):
            sub("Сертификат подписан неизвестным центром. Так выглядит")
            sub("перехват HTTPS: соединение работает, но читается посредником.")
            sub("Строки из сертификата: " + ", ".join(cert.get("strings", [])[:4]))
    else:
        line("сертификат", "не получен ({})".format(cert.get("error", "?")))

    print("\n  -- какие порты доживают до узла --")
    pm = port_matrix(ip)
    for k, r in pm.items():
        line(k, "открыт, {} мс".format(r["ms"]) if r.get("ok") else classify(r)[1])

    print("\n  -- path MTU --")
    mtu = path_mtu(ip)
    if mtu.get("ok"):
        line("максимальный пакет без фрагментации", "{} байт".format(mtu["mtu"]))
        if mtu["mtu"] < 1420:
            sub("Меньше 1420 — MTU туннеля стоит опустить до {}."
                .format(mtu["mtu"] - 80))
    else:
        line("path MTU", mtu.get("error", "?"))

    print("\n  -- QUIC (UDP:443) --")
    q = quic_probe(ip)
    line("QUIC до Google", q.get("verdict") if q.get("ok")
         else "FAIL — " + str(q.get("error")))
    if not q.get("ok"):
        sub("YouTube сильно опирается на QUIC. Его блок даёт долгую загрузку")
        sub("и обрывы видео при формально живом HTTPS.")

    print("\n  -- устойчивость: три попытки подряд --")
    # Фильтрация бывает плавающей: срабатывает не на каждое соединение.
    # Разовая проба такое пропускает и даёт ложное «всё чисто».
    stab = {"tls": [], "dns": []}
    for _ in range(3):
        stab["tls"].append(bool(tls_probe(ip, "www.youtube.com",
                                          timeout=4).get("ok")))
        time.sleep(0.3)
    tls_ok = sum(stab["tls"])
    line("TLS с именем youtube", "{} из 3 успешно".format(tls_ok))
    if 0 < tls_ok < 3:
        sub("Соединение проходит не всегда — фильтр срабатывает выборочно.")
        sub("Это типично для перегруженного DPI: часть сессий проскакивает.")
    stab["tls_ok"] = tls_ok

    print("\n  -- страница-заглушка по HTTP --")
    bp = http_blockpage("youtube.com")
    if bp.get("ok"):
        line("http://youtube.com/", "HTTP {} -> {}".format(
            bp["code"], bp["final_url"][:48]))
        if bp.get("blockpage"):
            sub("НАЙДЕНА ЗАГЛУШКА. Маркеры: " + ", ".join(bp["markers"]))
            sub("Провайдер подменяет содержимое на 80-м порту.")
    else:
        line("http://youtube.com/", classify(bp)[1])

    print("\n  -- прямой запрос к YouTube --")
    http = {}
    try:
        req = urllib.request.Request("https://www.youtube.com/",
                                     headers={"User-Agent": "Mozilla/5.0"})
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(2048)
            http = {"ok": True, "code": r.getcode(), "bytes": len(body),
                    "ms": int((time.time() - t0) * 1000)}
        line("GET https://www.youtube.com/", "HTTP {} — {} байт".format(
            http["code"], http["bytes"]))
    except Exception as e:
        http = {"ok": False, "error": type(e).__name__ + ": " + str(e)[:70]}
        line("GET https://www.youtube.com/", "FAIL — " + http["error"])

    ext = {}
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=TIMEOUT) as r:
            ext["ip"] = r.read().decode().strip()
        line("внешний IP", ext["ip"])
    except Exception as e:
        line("внешний IP", "не определён ({})".format(type(e).__name__))

    RESULT["transport"] = {"ip": ip, "tcp": tcp, "sni": sni_res, "origin": origin,
                           "trusted_ip": trusted, "quic": q, "http": http,
                           "external": ext, "scope": scope, "cert": cert, "blockpage": bp,
                           "stability": stab,
                           "ports": pm, "mtu": mtu}
    return sni_res, tcp, q, http


# ==========================================================================
# Вердикт клиента
# ==========================================================================

def client_verdict(dns_in_tunnel, web_in_tunnel, has_tunnel, data,
                   sni_res, tcp, quic, http):
    section("ИТОГ")

    problems = []
    notes = []

    # --- DNS ---
    # Подделанные ответы успехом не считаются нигде.
    # Разделы могли не заполниться при обрыве проверок, поэтому доступ
    # везде безопасный: вердикт обязан выдаваться даже по неполным данным.
    def entries(part):
        """Плоский список (ключ, запись) из раздела любой вложенности."""
        out = []
        for k, v in dget(data, part).items():
            if isinstance(v, dict):
                if all(isinstance(x, dict) for x in v.values()) and v:
                    out.extend((k, r) for r in v.values())
                else:
                    out.append((k, v))
        return out

    intercepted = bool(data.get("intercepted")) if isinstance(data, dict) else False
    sys_ok = (any(r.get("ok") and r.get("ips")
                  for _, r in entries("system"))
              and not intercepted)
    ext_ok = any(r.get("ok") and r.get("ips") and not r.get("suspect")
                 for _, r in entries("resolvers"))
    doh_ok = any(r.get("ok") and r.get("ips") for _, r in entries("doh"))
    pub = [x[0] for x in PUBLIC_RESOLVERS]
    udp53_ok = any(r.get("ok") and not r.get("suspect")
                   for k, r in entries("resolvers") if k in pub)
    tcp53_ok = any(r.get("ok") for _, r in entries("tcp53"))

    if dlist(data, "injected"):
        problems.append(
            "ИНЪЕКЦИЯ DNS: на один запрос пришло два разных ответа — подставной\n"
            "    первым, настоящий следом. Обычный резолвер принимает первый и\n"
            "    молча уводит тебя не туда. Открытый :53 использовать нельзя,\n"
            "    только DoH/DoT или резолвер внутри туннеля.")

    if intercepted:
        bh_ips = [x for x in dlist(dget(data, "blackhole"), "ips")
                  if isinstance(x, str)]
        problems.append(
            "Прозрачный перехват DNS: ответил адрес, где резолвера не существует.\n"
            "    Провайдер перехватывает весь порт 53 и подставляет свои ответы.\n"
            "    Указывать 8.8.8.8 или 1.1.1.1 системным DNS БЕСПОЛЕЗНО — их\n"
            "    ответы тоже подменяются. Помогает только DoH/DoT или резолвер\n"
            "    внутри туннеля." +
            ("\n    Подставляемые адреса: " + ", ".join(bh_ips[:3]) if bh_ips else ""))

    # Отличаем локальный запрет (kill switch) от блокировки провайдером.
    # Внешне и то и другое выглядит как «UDP:53 не работает», но причины
    # противоположные: первое — своя защита, второе — чужой фильтр.
    ext_codes = [classify(r)[0] for k, r in entries("resolvers") if k in pub]
    local_block = bool(ext_codes) and all(c in ("blocked_local", "refused")
                                          for c in ext_codes)

    if not udp53_ok and doh_ok and not intercepted:
        if local_block:
            notes.append(
                "UDP:53 к внешним резолверам запрещён ЛОКАЛЬНО — так работает\n"
                "    kill switch клиента VPN, чтобы DNS не мог утечь мимо\n"
                "    туннеля. Это защита, а не блокировка. Всё правильно.")
        elif has_tunnel and dns_in_tunnel is True:
            notes.append(
                "UDP:53 наружу не проходит, но твой DNS идёт внутрь туннеля —\n"
                "    блокировка тебя не касается. Чинить нечего.")
        elif has_tunnel is None:
            notes.append(
                "UDP:53 к внешним резолверам не проходит. Причину назвать\n"
                "    нельзя: неизвестно, поднят ли туннель. Это может быть и\n"
                "    kill switch VPN (тогда всё правильно), и фильтр провайдера.\n"
                "    Прогони то же самое при заведомо выключенном VPN.")
        else:
            problems.append(
                "UDP:53 наружу закрыт, DoH работает -> провайдер режет порт 53.\n"
                "    Все обязаны пользоваться его резолвером, а тот вычищен.\n"
                "    Лечение: резолв внутрь туннеля либо DoH на клиенте." +
                ("\n    TCP:53 при этом жив — временный обход." if tcp53_ok else ""))

    if not sys_ok and (ext_ok or doh_ok):
        if dns_in_tunnel is True:
            problems.append(
                "Резолвер в туннеле не резолвит YouTube, а достоверные внешние\n"
                "    источники резолвят. Проблема на сервере: смотри режим server.")
        elif intercepted:
            problems.append(
                "Системный резолвер не резолвит YouTube. С учётом перехвата это\n"
                "    фильтр провайдера: он и подменяет, и вычищает записи.")
        else:
            problems.append(
                "Системный резолвер не резолвит YouTube, внешние резолвят.\n"
                "    Это фильтр на резолвере провайдера (типовой НСДИ-сценарий).")

    # dns_in_tunnel может быть None — интерфейсы не перечислены. Утечку
    # утверждаем только когда она действительно установлена.
    if has_tunnel and dns_in_tunnel is False:
        problems.append(
            "DNS уходит МИМО туннеля. Даже при живом VPN имена резолвит\n"
            "    провайдер, и его фильтр работает. Проверь DNS= в конфиге\n"
            "    и AllowedIPs, на Android — отключи Частный DNS.")
    elif dns_in_tunnel is None:
        notes.append(
            "Определить, идёт ли DNS через туннель, не удалось: система не\n"
            "    даёт перечислить интерфейсы (типично для Termux). Проверки\n"
            "    DNS и транспорта ниже при этом достоверны.")

    if RESULT.get("routing", {}).get("ipv6") and has_tunnel:
        notes.append(
            "Есть выход по IPv6. Если туннель только IPv4 — часть трафика\n"
            "    идёт мимо него. Стоит отключить IPv6 либо завести его в туннель.")

    if (not dget(data, "big_udp").get("ok")
            and dget(data, "small_udp").get("ok")):
        problems.append(
            "Короткие DNS-ответы проходят, длинные нет -> блэкхол по MTU.\n"
            "    Уменьши MTU туннеля (обычно 1420 -> 1280).")

    # --- Транспорт ---
    yt = [v for k, v in sni_res.items() if "youtube" in k or "ytimg" in k]
    ctrl = [v for k, v in sni_res.items() if "google.com" in k or "example" in k]
    yt_ok = all(v.get("ok") for v in yt) if yt else False
    ctrl_ok = all(v.get("ok") for v in ctrl) if ctrl else False
    verdicts = {v.get("verdict") for v in yt if not v.get("ok")}

    trusted_ip = dget(RESULT, "transport").get("trusted_ip", True)
    if not tcp.get("ok") and trusted_ip:
        problems.append(
            "TCP:443 до Google не открывается вообще -> блок по IP.\n"
            "    Это грубее SNI-фильтра и обходится только туннелем.")
    elif not tcp.get("ok"):
        notes.append(
            "Проверки транспорта не проведены: достоверный IP получить не\n"
            "    удалось (DNS сломан), а запасные адреса не отвечают. Это не\n"
            "    доказывает блокировку — сначала почини резолв.")
    elif ctrl_ok and not yt_ok:
        how = ("RST-инъекция (активный DPI)" if "rst" in verdicts
               else "тихий drop пакетов" if "timeout" in verdicts else "обрыв")
        problems.append(
            "Один IP, разные имена: google проходит, youtube рвётся.\n"
            "    Механизм: {}. Это фильтр по SNI на транзите.\n"
            "    Имя видно снаружи -> резолв и sniffing должны быть на сервере."
            .format(how))
    elif yt_ok:
        notes.append("TLS с именем youtube проходит — транспорт по 443 цел.")

    nx = dget(data, "nxdomain")
    if nx.get("hijacked"):
        problems.append(
            "Резолвер отдаёт адрес на НЕСУЩЕСТВУЮЩЕЕ имя вместо NXDOMAIN.\n"
            "    Провайдер уводит любой неизвестный домен на свою страницу.\n"
            "    Побочный вред: ломаются внутренние имена и поиск по домену.")

    xc = dget(data, "cross_check")
    if xc.get("suspicious"):
        problems.append(
            "Открытый :53 и DoH дают адреса из РАЗНЫХ сетей ({} против {}).\n"
            "    DoH подделать нельзя — значит врёт открытый 53. Это прямая\n"
            "    улика подмены, независимая от прочих проверок."
            .format(", ".join(xc.get("plain", [])[:1]),
                    ", ".join(xc.get("doh", [])[:1])))

    ds = dget(data, "dnssec")
    if ds.get("ok") and not ds.get("validates"):
        notes.append(
            "Резолвер не проверяет подписи DNSSEC. Само по себе не поломка,\n"
            "    но с валидацией подмену было бы видно на уровне DNS.")

    tr = dget(RESULT, "transport")
    cert = dget(tr, "cert")
    if cert.get("ok") and not cert.get("known_ca"):
        problems.append(
            "Сертификат подписан НЕИЗВЕСТНЫМ центром — похоже на перехват\n"
            "    HTTPS. Соединение работает, но содержимое видно посреднику.\n"
            "    Проверь, не стоит ли антивирус с проверкой SSL, и не\n"
            "    подсунут ли в систему чужой корневой сертификат.")

    st = dget(tr, "stability")
    if st and 0 < st.get("tls_ok", 3) < 3:
        problems.append(
            "Нестабильная фильтрация: из трёх одинаковых попыток прошло {}.\n"
            "    Блокировка срабатывает не на каждое соединение, поэтому\n"
            "    одиночная проверка легко покажет «всё чисто». Ориентируйся\n"
            "    на этот пункт, а не на разовый успех выше."
            .format(st["tls_ok"]))

    bp = dget(tr, "blockpage")
    if bp.get("blockpage"):
        problems.append(
            "По HTTP отдаётся страница-заглушка провайдера (маркеры: {}).\n"
            "    Незашифрованный трафик подменяется на транзите."
            .format(", ".join(bp.get("markers", [])[:3])))

    scope = dget(tr, "scope")
    if scope:
        blocked = [l for sni, l in SCOPE_SNI
                   if sni in scope and not dget(scope, sni).get("ok")
                   and "контроль" not in l]
        if len(blocked) > 1:
            notes.append(
                "Фильтр по имени задевает не только YouTube: " +
                ", ".join(blocked[:5]) + ".\n"
                "    Это общая политика на транзите, а не точечная блокировка.")

    mtu = dget(tr, "mtu")
    if mtu.get("ok") and mtu.get("mtu", 1500) < 1420:
        problems.append(
            "Path MTU всего {} байт. При MTU туннеля 1420 длинные пакеты\n"
            "    будут теряться: короткие запросы проходят, страницы виснут.\n"
            "    Опусти MTU в конфиге до {}.".format(mtu["mtu"], mtu["mtu"] - 80))

    ports = dget(tr, "ports")
    alive = [k for k, r in ports.items() if isinstance(r, dict) and r.get("ok")]
    if ports and not tcp.get("ok") and alive:
        notes.append(
            "443 не работает, но живы другие порты: " + ", ".join(alive) + ".\n"
            "    Точку входа можно переставить на один из них.")

    if not quic.get("ok") and trusted_ip and tcp.get("ok"):
        problems.append(
            "QUIC (UDP:443) не проходит, при живом TCP:443. HTTPS работает,\n"
            "    но видео будет буферить и рваться. Часто режут QUIC отдельно.")

    if http.get("ok") and http.get("code") == 200 and problems:
        notes.append(
            "При этом сама страница YouTube отдаётся (HTTP 200) — значит\n"
            "    поломка выше по стеку, в резолве или в клиенте, не в сети.")

    # --- Печать ---
    # Отличаем «проверки прошли, блокировок нет» от «проверить не удалось».
    # Раньше оба случая давали «блокировок не найдено», и полный отказ сети
    # читался как чистая сеть — самый вредный из возможных выводов.
    measured = (sys_ok or ext_ok or doh_ok or tcp.get("ok")
                or any(v.get("ok") for v in sni_res.values()
                       if isinstance(v, dict)))
    if not problems and not measured:
        print("  ДАННЫХ НЕТ: ни одна проверка не дала результата.")
        print("  Не резолвится ничего, транспорт не отвечает, DoH недоступен.")
        print("  Это НЕ значит «чисто» — значит, измерить не удалось.")
        print("  Проверь физическую связь, затем повтори прогон.")
    elif not problems:
        print("  Явных блокировок не найдено.")
        if has_tunnel and dns_in_tunnel is True and web_in_tunnel is True:
            print("  Трафик и DNS идут внутрь туннеля — конфигурация верная.")
    else:
        for p in problems:
            print("  * " + p)
    if notes:
        print()
        for n in notes:
            print("  - " + n)

    # --- что делать: конкретные шаги в порядке важности ---
    steps = []
    if intercepted or dget(data, "cross_check").get("suspicious") \
            or dlist(data, "injected") or dget(data, "nxdomain").get("hijacked"):
        steps.append("Увести DNS от провайдера: резолвер внутри туннеля "
                     "(DNS = <адрес> в конфиге) либо DoH/DoT на клиенте. "
                     "Указывать 8.8.8.8 по обычному :53 бесполезно.")
    if has_tunnel and dns_in_tunnel is False:
        steps.append("Проверить DNS= и AllowedIPs в конфиге; на Android "
                     "выключить Частный DNS.")
    if dget(RESULT, "transport", "cert").get("ok") and \
            not dget(RESULT, "transport", "cert").get("known_ca"):
        steps.append("Найти, кто вклинивается в HTTPS: антивирус с проверкой "
                     "SSL, корпоративный прокси или чужой корневой сертификат.")
    mtu_v = dget(RESULT, "transport", "mtu").get("mtu")
    if mtu_v and mtu_v < 1420:
        steps.append("Опустить MTU туннеля до {}.".format(mtu_v - 80))
    if any("SNI" in p or "имени" in p for p in problems):
        steps.append("Держать трафик в туннеле: внутри него имя не видно, "
                     "фильтр по SNI не работает.")
    if not steps and problems:
        steps.append("Поднять VPN и повторить прогон — под туннелем "
                     "большинство найденного перестаёт действовать.")

    if steps:
        print("\n  ЧТО ДЕЛАТЬ")
        for i, stp in enumerate(steps, 1):
            # Перенос строго по словам: рвать слова посреди — нечитаемо.
            words, cur, out = stp.split(), "", []
            for w in words:
                if len(cur) + len(w) + 1 > 66:
                    out.append(cur)
                    cur = w
                else:
                    cur = (cur + " " + w).strip()
            if cur:
                out.append(cur)
            print("  {}. {}".format(i, out[0] if out else ""))
            for extra in out[1:]:
                print("     " + extra)

    print("\n  Прогон без VPN и с VPN, затем:")
    print("    python3 netprobe.py compare novpn.json vpn.json")

    RESULT["verdict"] = {"problems": problems, "notes": notes, "steps": steps}


def parse_txt(buf, tid):
    """Извлечь TXT-строки из ответа DNS.

    Регулярка по сырым байтам тут не годится: перед каждой строкой стоит
    байт длины, и если он попадает в печатаемый диапазон, то приклеивается
    к тексту и искажает данные — например, номер AS.
    """
    if len(buf) < 12:
        return []
    rid, _, qd, an, _, _ = struct.unpack(">HHHHHH", buf[:12])
    if rid != tid:
        return []
    off = 12
    for _ in range(qd):
        off = skip_name(buf, off) + 4
    out = []
    for _ in range(an):
        try:
            off = skip_name(buf, off)
            rtype, _, _, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        except Exception:
            break
        off += 10
        end = off + rdlen
        if rtype == 16:
            pos = off
            while pos < end and pos < len(buf):
                ln = buf[pos]
                out.append(buf[pos + 1:pos + 1 + ln].decode("utf-8", "replace"))
                pos += 1 + ln
        off = end
    return out


def lookup_asn(ip):
    """ASN и страна по IP через публичный whois-сервис Team Cymru.

    Обычный DNS-запрос TXT — работает без ключей и регистрации. ASN
    заменяет и IP, и название провайдера: он достаточно точен, чтобы
    сравнивать замеры между сетями, и недостаточно, чтобы указать
    на конкретного человека.
    """
    try:
        rev = ".".join(reversed(ip.split(".")))
        qname = "{}.origin.asn.cymru.com".format(rev)
        tid, pkt = build_query(qname, qtype=16)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            sock.sendto(pkt, ("8.8.8.8", 53))
            buf, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        strings = parse_txt(buf, tid)
        if not strings:
            return None
        parts = [x.strip() for x in strings[0].split("|")]
        if len(parts) < 3:
            return None
        # В начале TXT-записи стоит байт длины и служебные символы —
        # берём из первого поля только цифры номера AS.
        m = re.search(r"(\d+)", parts[0])
        if not m:
            return None
        pref = re.search(r"[\d.]+/\d+", parts[1])
        ctry = re.search(r"[A-Z]{2}", parts[2])
        return {"asn": "AS" + m.group(1),
                "prefix": pref.group(0) if pref else "",
                "country": ctry.group(0) if ctry else ""}
    except Exception:
        return None


def anonymize(result):
    """Убрать из результата всё, что указывает на конкретного человека.

    Остаётся то, что нужно для сравнения между сетями: ASN, страна,
    указанный пользователем регион, дата и сами результаты проверок.
    Уходит: внешний IP, адреса резолверов и тестовых узлов, локальные
    интерфейсы и подсети, имена контейнеров, пути к файлам.
    """
    drop_keys = {"external", "ifaces", "tunnels", "src_web", "src_dns",
                 "src_local", "ipv6", "containers", "listeners", "resolver",
                 "egress", "firewall", "routing", "transport", "android",
                 "hostname", "host", "path", "strings", "final_url"}

    def clean(obj, in_asn=False):
        if isinstance(obj, dict):
            return {k: clean(v, in_asn or k == "asn")
                    for k, v in obj.items() if k not in drop_keys}
        if isinstance(obj, list):
            return [clean(v, in_asn) for v in obj]
        if isinstance(obj, str):
            # Блок ASN не трогаем: префикс сети — это /24 провайдера, он
            # и нужен для сводки и не указывает на конкретный узел.
            if in_asn:
                return obj
            # В остальном тексте любой IPv4/IPv6 — вон, включая подписи.
            out = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<ip>", obj)
            # Пути содержат имя пользователя — самая недооценённая утечка.
            out = re.sub(r"/home/[^/\s\"]+", "/home/<user>", out)
            out = re.sub(r"/Users/[^/\s\"]+", "/Users/<user>", out)
            out = re.sub(r"([Cc]:)?\\Users\\[^\\\s\"]+",
                         lambda m: (m.group(1) or "") + r"\Users\<user>", out)
            out = re.sub(r"/root/[^/\s\"]*", "/root/<...>", out)
            out = re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{0,4}\b",
                         "<ipv6>", out)
            return out
        return obj

    return clean(result)


def load_scan_list(path):
    """Свой список имён из файла: одно имя в строке, необязательная
    подпись через пробел или запятую. Строки с # игнорируются."""
    groups = []
    skipped = []
    dupes = []
    seen = set()
    cur = ("Свой список", [])
    try:
        with open(path, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                if ln.startswith("##"):
                    if cur[1]:
                        groups.append(cur)
                    cur = (ln.lstrip("#").strip(), [])
                    continue
                if ln.startswith("#"):
                    continue
                parts = re.split(r"[,\s]+", ln, maxsplit=1)
                host = to_punycode(parts[0].strip().rstrip("."))
                label = parts[1].strip() if len(parts) > 1 else host
                # Невалидное имя всегда провалит рукопожатие, и в отчёте
                # это выглядит как блокировка. То есть опечатка в списке
                # читается как цензура — поэтому отсеиваем сразу.
                if not valid_hostname(host):
                    skipped.append(parts[0][:40])
                    continue
                # Результаты хранятся словарём по имени, поэтому дубликат
                # проверялся бы дважды, но в отчёт попал бы один раз —
                # счётчики разошлись бы с содержимым.
                if host in seen:
                    dupes.append(host)
                    continue
                seen.add(host)
                cur[1].append((host, label[:60]))
    except Exception as e:
        print("Не удалось прочитать список: {}".format(e))
        return None
    if cur[1]:
        groups.append(cur)
    if dupes:
        print("  Пропущено повторов: {} ({})".format(
            len(dupes), ", ".join(dupes[:4])))
    if skipped:
        print("  Пропущено некорректных имён: {} ({})".format(
            len(skipped), ", ".join(skipped[:4])))
        print("  Такие имена всегда провалили бы проверку и выглядели бы")
        print("  как блокировка. Проверь опечатки.")
    return groups or None


def to_punycode(host):
    """Кириллическое имя -> punycode.

    Домены вроде почта.рф вполне законны, но в SNI и в DNS идут только
    в ASCII-форме. Без преобразования они отсеивались бы как «некорректные»,
    хотя проверить их — совершенно нормальное желание.
    """
    h = (host or "").strip().rstrip(".")
    if not h:
        return ""
    try:
        h.encode("ascii")
        return h.lower()
    except UnicodeEncodeError:
        pass
    try:
        return h.encode("idna").decode("ascii").lower()
    except Exception:
        # Кодировать по меткам: некоторые имена целиком idna не берёт.
        out = []
        for lbl in h.split("."):
            try:
                out.append(lbl.encode("idna").decode("ascii"))
            except Exception:
                return h.lower()
        return ".".join(out).lower()


def valid_hostname(host):
    """Похоже ли на настоящее доменное имя.

    Требования намеренно строгие: только буквы, цифры, дефис и точки,
    минимум одна точка, длина метки до 63, всего до 253 символов.
    """
    if not host or len(host) > 253 or "." not in host:
        return False
    if host.startswith(".") or host.startswith("-") or ".." in host:
        return False
    labels = host.split(".")
    if len(labels[-1]) < 2:
        return False
    for lbl in labels:
        if not lbl or len(lbl) > 63:
            return False
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", lbl):
            return False
    return True


def mode_scan(args):
    """Карта фильтрации: что режется в этой сети, а что проходит.

    Отвечает не на вопрос «почему у меня сломалось» (для этого client),
    а на вопрос «какая политика фильтрации здесь действует». Результат
    осмысленно сравнивать между людьми и городами.
    """
    print("netprobe v{} — режим SCAN".format(VERSION))
    print("{} / Python {}".format(platform.platform(), platform.python_version()))
    RESULT["mode"] = "scan"
    RESULT["label"] = args.label
    RESULT["time"] = time.strftime("%Y-%m-%d %H:%M:%S")

    groups = load_scan_list(args.list) if args.list else SCAN_GROUPS
    if not groups:
        return 1

    # Нужен один живой узел: DPI реагирует на имя, а не на адрес.
    section("ПОДГОТОВКА")
    probe = {"doh": {}}
    for url, name in DOH_ENDPOINTS:
        r = doh_query(url, "www.google.com")
        if r.get("ok") and r.get("ips"):
            probe["doh"][name] = r
            break
    ip, origin, trusted = verified_ip(probe)
    line("тестовый узел", "{} ({})".format(ip, origin))
    if not trusted:
        sub("Достоверный узел не получен — результаты будут ненадёжны.")
    tcp = tcp_probe(ip, 443)
    line("TCP:443 до узла", "открыт" if tcp.get("ok") else classify(tcp)[1])
    if not tcp.get("ok"):
        sub("Узел недоступен: проверять фильтрацию по именам не на чем.")
        return 1

    ext = None
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=TIMEOUT) as r:
            ext = r.read().decode().strip()
        if getattr(args, "anon", False):
            line("внешний IP", "скрыт (режим --anon)")
        else:
            line("внешний IP", ext)
            RESULT["external"] = ext
    except Exception:
        line("внешний IP", "не определён")

    # ASN заменяет и адрес, и название провайдера: достаточно для сравнения
    # сетей между собой, недостаточно для указания на человека.
    if ext:
        asn = lookup_asn(ext)
        if asn:
            line("сеть", "{} {} {}".format(asn["asn"], asn["prefix"],
                                           asn["country"]))
            RESULT["asn"] = asn
        else:
            line("сеть", "ASN не определён")
    if getattr(args, "region", None):
        line("регион", args.region)
        RESULT["region"] = args.region
    elif getattr(args, "anon", False):
        sub("Регион не указан. Для сводки он полезен: --region \"Донецк\"")

    results = {}
    totals = {"проходит": 0, "режется": 0, "иное": 0}
    RESULT["scan"] = results          # ссылка живая: уцелеет при обрыве
    RESULT["totals"] = totals
    for gname, items in groups:
        section(gname.upper())
        for host, label in items:
            r = tls_probe(ip, host, timeout=4)
            results[host] = {"label": label, "group": gname,
                             "ok": bool(r.get("ok")), "verdict": r.get("verdict")}
            if r.get("ok"):
                totals["проходит"] += 1
                line(label, "проходит")
            elif r.get("verdict") in ("rst", "timeout"):
                totals["режется"] += 1
                line(label, "режется ({})".format(
                    "RST" if r.get("verdict") == "rst" else "drop"))
            else:
                totals["иное"] += 1
                line(label, classify(r)[1])

    section("СВОДКА")
    ctrl = [v for v in results.values() if "Контроль" in v["group"]]
    ctrl_ok = all(v["ok"] for v in ctrl) if ctrl else None
    line("проходит", totals["проходит"])
    line("режется", totals["режется"])
    if totals["иное"]:
        line("прочие исходы", totals["иное"])

    blocked = [v["label"] for v in results.values()
               if not v["ok"] and "Контроль" not in v["group"]]
    print()
    checked = len(results)
    if ctrl_ok is False:
        sub("Контрольные имена НЕ проходят — сломан сам канал, а не фильтр.")
        sub("Результаты ниже ничего не значат, проверь связь и повтори.")
    elif ctrl_ok is None and checked and totals["проходит"] == 0:
        # Свой список без контрольной группы: сплошной провал одинаково
        # выглядит и как тотальная блокировка, и как оборванная связь.
        sub("НЕ ПРОШЛО НИ ОДНО имя, а контрольной группы в списке нет —")
        sub("отличить тотальную блокировку от обрыва связи невозможно.")
        sub("Добавь в список заведомо доступное имя, например example.com.")
    elif not blocked:
        sub("Фильтрации по именам не обнаружено.")
    else:
        sub("Режется: " + ", ".join(blocked[:12]) +
            (" и ещё {}".format(len(blocked) - 12) if len(blocked) > 12 else ""))
        by_group = {}
        for v in results.values():
            if not v["ok"] and "Контроль" not in v["group"]:
                by_group[v["group"]] = by_group.get(v["group"], 0) + 1
        print()
        for g, n in sorted(by_group.items(), key=lambda x: -x[1]):
            total_g = sum(1 for v in results.values() if v["group"] == g)
            sub("{:<38} {} из {}".format(g[:38], n, total_g))
        dns_hit = any(not v["ok"] for v in results.values()
                      if "DNS" in v["group"])
        if dns_hit:
            print()
            sub("Задет шифрованный DNS — это ломает резолв целиком, а не")
            sub("отдельный сайт. Резолвер нужно уводить внутрь туннеля.")

    RESULT["scan"] = results
    RESULT["totals"] = totals
    return 0


def stage(name, fn, *a, **kw):
    """Выполнить раздел проверки, пережив его падение.

    Диагностика идёт по сети и может занять минуты. Если один раздел
    упадёт из-за неожиданной ошибки, терять уже собранное нельзя —
    остальные разделы и сохранение результата должны отработать.
    """
    try:
        return fn(*a, **kw), True
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print()
        line("раздел «{}»".format(name), "прерван ошибкой: {}".format(
            type(e).__name__))
        sub("Остальные проверки продолжатся, результат будет неполным.")
        RESULT.setdefault("errors", []).append(
            {"stage": name, "error": type(e).__name__, "detail": str(e)[:120]})
        return None, False


def save_result(args, note=""):
    """Записать результат, если запрошен --json. Вызывается и при обрыве."""
    path = getattr(args, "json", None)
    if not path:
        return
    # Пишем во временный файл рядом и переименовываем. Прямая запись
    # при обрыве (нет места, Ctrl+C) оставляет обрезанный JSON на месте
    # прежнего — то есть портит и новый результат, и старый.
    tmp = path + ".tmp"
    try:
        payload = anonymize(RESULT) if getattr(args, "anon", False) else RESULT
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=1)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        print("Результат сохранён: {}{}".format(path, note))
    except Exception as e:
        print("Не удалось сохранить JSON: {}".format(e))
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def mode_client(args):
    print("netprobe v{} — режим КЛИЕНТ — метка '{}'".format(VERSION, args.label))
    print("{} / Python {}".format(platform.platform(), platform.python_version()))
    RESULT["mode"] = "client"
    RESULT["label"] = args.label
    RESULT["time"] = time.strftime("%Y-%m-%d %H:%M:%S")

    r, ok = stage("маршрутизация", routing_report, args.dns)
    dns_in_tunnel, web_in_tunnel, has_tunnel = r if ok else (None, None, None)

    data, ok = stage("DNS", dns_report, args.dns)
    if not ok or not isinstance(data, dict):
        data = {}

    r, ok = stage("транспорт", transport_report, data)
    sni_res, tcp, quic, http = r if ok else ({}, {"ok": False}, {"ok": False}, {})

    stage("вердикт", client_verdict, dns_in_tunnel, web_in_tunnel, has_tunnel,
          data, sni_res, tcp, quic, http)


# ==========================================================================
# Серверный режим
# ==========================================================================

def server_listeners():
    section("1. КТО СЛУШАЕТ :53 НА СЕРВЕРЕ")
    udp = run("ss -ulnp 2>/dev/null | grep ':53 '") or ""
    tcp = run("ss -tlnp 2>/dev/null | grep ':53 '") or ""

    print("  -- UDP --")
    for ln in (udp.strip().splitlines() or ["  (пусто)"]):
        sub(ln.strip())
    print("  -- TCP --")
    for ln in (tcp.strip().splitlines() or ["  (пусто)"]):
        sub(ln.strip())

    lines53 = [ln for ln in (udp + "\n" + tcp).splitlines() if ":53" in ln]
    # [::]:53 — тоже привязка ко всем интерфейсам, и через IPv6 открытый
    # резолвер находят так же быстро, как через IPv4.
    wildcard = bool(re.search(r"(^|\s)(0\.0\.0\.0|\*|\[::\]):53\s", udp + tcp))
    only_loop = bool(lines53) and all(
        "127.0.0." in ln or "[::1]" in ln for ln in lines53)

    print()
    if not lines53:
        line("привязка", "никто не слушает :53 на хосте")
        sub("Либо резолвера нет, либо он в контейнере со своим netns —")
        sub("тогда с хоста его не видно, смотри список контейнеров ниже.")
    elif wildcard:
        line("привязка", "все интерфейсы (0.0.0.0 или [::]) — открыт наружу")
        sub("Риск: открытый резолвер, DNS-amplification и абуза от хостера.")
    elif only_loop:
        dns_in_docker = "dns" in (run("docker ps --format '{{.Names}}'") or "").lower()
        if dns_in_docker:
            line("привязка на хосте", "только loopback (это systemd-resolved)")
            sub("Настоящий резолвер — в контейнере, у него свой netns.")
            sub("Для клиентов туннеля это нормально, см. раздел 2.")
        else:
            line("привязка", "только loopback — клиентам туннеля недоступен")
    else:
        line("привязка", "на конкретных адресах (правильно)")

    dock = run("docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'")
    containers = []
    if dock:
        print("\n  -- контейнеры --")
        for ln in dock.strip().splitlines():
            sub(ln)
            containers.append(ln)
        sub("")
        sub("Контейнер с DNS в своём netns на хостовом ss не виден — это норма.")

    RESULT["listeners"] = {"udp": udp, "tcp": tcp, "wildcard": wildcard,
                           "containers": containers}
    return wildcard


def server_resolver(addr):
    section("2. РЕЗОЛВЕР — работает ли и рекурсивен ли")
    if not addr:
        # попробуем угадать адрес docker-контейнера amnezia-dns
        guess = run("docker inspect -f "
                    "'{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "
                    "amnezia-dns 2>/dev/null")
        # Контейнер может быть в нескольких сетях — берём первый валидный IPv4.
        if guess:
            m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", guess)
            if m:
                addr = m.group(1)
                line("найден amnezia-dns", addr)
    if not addr:
        sub("Адрес резолвера не задан и не найден. Укажи --dns.")
        RESULT["resolver"] = {"addr": None}
        return None

    res = {"addr": addr}
    for d in ["www.youtube.com", "youtubei.googleapis.com", "www.google.com"]:
        r = dns_udp(addr, d)
        res[d] = r
        line(d, fmt(r))

    # Случайное имя — проверяем именно рекурсию, а не кэш.
    rnd = "probe{}.example.com".format(random.randint(10000, 99999))
    r = dns_udp(addr, rnd)
    res["recursion"] = r
    line("рекурсия (случайное имя)",
         "работает ({})".format(r.get("rcode")) if r.get("ok")
         else "FAIL — " + str(r.get("error")))

    tcpr = dns_tcp(addr, "www.youtube.com")
    res["tcp"] = tcpr
    line("TCP:53 на резолвере", fmt(tcpr))
    if not tcpr.get("ok"):
        sub("Длинные ответы и DNSSEC пойдут по TCP. Закрытый TCP:53 даёт")
        sub("случайные подвисания, которые легко спутать с блокировкой.")

    RESULT["resolver"] = res
    return res


def server_egress():
    section("3. ВЫХОД С СЕРВЕРА НАРУЖУ")
    eg = {}
    for ip, name in PUBLIC_RESOLVERS[:2]:
        r = dns_udp(ip, "www.youtube.com")
        eg["udp53_" + name] = r
        line("UDP:53 -> {} ({})".format(ip, name), fmt(r))

    r = dns_tcp("8.8.8.8", "www.youtube.com")
    eg["tcp53"] = r
    line("TCP:53 -> 8.8.8.8", fmt(r))

    for url, name in DOH_ENDPOINTS[:1]:
        r = doh_query(url, "www.youtube.com")
        eg["doh_" + name] = r
        line("DoH " + name, fmt(r))

    doh_only = {"doh": {k: v for k, v in eg.items() if k.startswith("doh")}}
    ip, origin, trusted = verified_ip(doh_only)
    eg["test_ip"] = ip
    eg["trusted_ip"] = trusted
    line("тестовый IP Google", "{} ({})".format(ip, origin))
    if not trusted:
        sub("Достоверный адрес не получен — выводы по TLS и QUIC ненадёжны.")

    t = tls_probe(ip, "www.youtube.com")
    eg["tls"] = t
    line("TLS с SNI youtube", "проходит" if t.get("ok")
         else "{} — {}".format(t.get("verdict"), t.get("error")))

    q = quic_probe(ip)
    eg["quic"] = q
    line("QUIC (UDP:443)", q.get("verdict") if q.get("ok")
         else "FAIL — " + str(q.get("error")))

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=TIMEOUT) as r:
            eg["external"] = r.read().decode().strip()
        line("внешний IP сервера", eg["external"])
    except Exception:
        line("внешний IP сервера", "не определён")

    RESULT["egress"] = eg
    return eg


def server_firewall():
    section("4. ФАЙРВОЛ И КОНФИГУРАЦИЯ")
    fw = {}
    ufw = run("ufw status verbose 2>/dev/null")
    if ufw and "Status" in ufw:
        fw["ufw"] = ufw
        for ln in ufw.strip().splitlines():
            if "53" in ln or "Status" in ln or "Default" in ln:
                sub(ln.strip())
    else:
        ipt = run("iptables -S 2>/dev/null | grep -E 'dpt:53|--dport 53'")
        fw["iptables"] = ipt or ""
        if ipt and ipt.strip():
            for ln in ipt.strip().splitlines():
                sub(ln.strip())
        else:
            sub("Правил по порту 53 не найдено (или нет прав — запусти под sudo).")

    print()
    rules = fw.get("ufw", "") + fw.get("iptables", "")
    has_udp = bool(re.search(r"53(/|\s+\S*\s*)?udp", rules, re.I))
    has_tcp = bool(re.search(r"53(/|\s+\S*\s*)?tcp", rules, re.I))
    # Правило вида "53 ALLOW IN ..." без протокола покрывает оба сразу.
    bare = bool(re.search(r"^\s*53\s+(ALLOW|DENY|REJECT)", rules, re.I | re.M))
    if bare:
        has_udp = has_tcp = True
    line("правило для UDP:53", "есть" if has_udp else "НЕ НАЙДЕНО")
    line("правило для TCP:53", "есть" if has_tcp else "НЕ НАЙДЕНО")

    # XRay: sniffing определяет домен на сервере, а не на клиенте
    print()
    xray_paths = ["/opt/amnezia/xray/server.json", "/usr/local/etc/xray/config.json",
                  "/etc/xray/config.json", "/opt/amnezia/xray/config.json"]
    sniff = None
    found_cfg = False
    for p in xray_paths:
        if os.path.exists(p):
            found_cfg = True
            try:
                with open(p, encoding="utf-8") as f:
                    cfg = json.load(f)
                inb = cfg.get("inbounds", [])
                sniff = any((i.get("sniffing") or {}).get("enabled") for i in inb)
                line("конфиг XRay", p)
                line("sniffing включён", "ДА" if sniff else "НЕТ")
                if not sniff:
                    sub("Без sniffing домен определяется на клиенте, и имя может")
                    sub("утечь в открытом виде. Включи sniffing в inbounds.")
            except Exception as e:
                line("конфиг XRay", "{} — не разобран ({})".format(p, type(e).__name__))
                sub("Файл есть, но прочитать не удалось. Проверь синтаксис —")
                sub("XRay с таким конфигом тоже не стартует.")
            break
    if not found_cfg:
        line("конфиг XRay", "не найден в стандартных путях")
        sub("Если XRay стоит в контейнере, конфиг лежит внутри него.")
    fw["xray_sniffing"] = sniff

    # Туннельные интерфейсы: MTU и адреса
    print()
    ipout = run("ip -o link show 2>/dev/null") or ""
    tun_ifaces = []
    for ln in ipout.splitlines():
        m = re.match(r"\d+:\s+(\S+?)[@:]", ln)
        if m and looks_like_tunnel(m.group(1)):
            mtu_m = re.search(r"mtu (\d+)", ln)
            tun_ifaces.append((m.group(1), int(mtu_m.group(1)) if mtu_m else None))
    if tun_ifaces:
        for name, mtu in tun_ifaces:
            line("туннель {}".format(name), "MTU {}".format(mtu or "?"))
            if mtu and mtu > 1420:
                sub("MTU выше 1420 — на плохом пути начнутся потери длинных")
                sub("пакетов: короткие запросы идут, страницы виснут.")
    else:
        line("туннельные интерфейсы", "не найдены на хосте")
    fw["tunnels"] = tun_ifaces

    # Пересылка пакетов: без неё клиенты не выйдут наружу
    fwd = run("sysctl -n net.ipv4.ip_forward 2>/dev/null")
    fwd6 = run("sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null")
    if fwd:
        line("ip_forward (IPv4)", "включена" if fwd.strip() == "1" else "ВЫКЛЮЧЕНА")
        if fwd.strip() != "1":
            sub("Без неё трафик клиентов наружу не пойдёт вообще.")
    if fwd6:
        line("forwarding (IPv6)", "включена" if fwd6.strip() == "1" else "выключена")
    fw["forward"] = {"v4": (fwd or "").strip(), "v6": (fwd6 or "").strip()}

    # Таблица соединений: переполнение рвёт сессии на ровном месте
    ct = run("sysctl -n net.netfilter.nf_conntrack_count 2>/dev/null")
    ctmax = run("sysctl -n net.netfilter.nf_conntrack_max 2>/dev/null")
    if ct and ctmax:
        try:
            cur, mx = int(ct.strip()), int(ctmax.strip())
            pct = 100 * cur // max(mx, 1)
            line("таблица соединений", "{} из {} ({}%)".format(cur, mx, pct))
            if pct > 80:
                sub("Больше 80% — при переполнении соединения начнут рваться")
                sub("без всякой блокировки. Подними nf_conntrack_max.")
            fw["conntrack"] = {"cur": cur, "max": mx, "pct": pct}
        except ValueError:
            pass

    # Время: расхождение ломает TLS и Reality
    try:
        with urllib.request.urlopen("https://www.google.com", timeout=TIMEOUT) as r:
            hdr = r.headers.get("Date")
        if hdr:
            import email.utils
            remote = email.utils.parsedate_to_datetime(hdr).timestamp()
            skew = int(abs(remote - time.time()))
            line("расхождение часов", "{} сек".format(skew))
            if skew > 60:
                sub("Больше минуты — Reality и TLS будут рваться. Проверь NTP.")
            fw["skew"] = skew
    except Exception:
        pass

    RESULT["firewall"] = fw


def server_verdict(wildcard, res, eg):
    section("ИТОГ ПО СЕРВЕРУ")
    problems, notes = [], []
    # Разделы могли не заполниться, если проверка оборвалась.
    res = res if isinstance(res, dict) else {}
    eg = eg if isinstance(eg, dict) else {}

    if wildcard:
        problems.append(
            "Резолвер слушает 0.0.0.0:53 — виден из интернета.\n"
            "    Его найдут за сутки и используют для amplification-атак.\n"
            "    Закрой: ufw allow in on <туннель> to any port 53 ; ufw deny 53")

    if res.get("addr"):
        yt = dget(res, "www.youtube.com")
        g = dget(res, "www.google.com")
        if not yt.get("ok") and g.get("ok"):
            problems.append(
                "Резолвер отдаёт google, но не youtube — фильтр на апстриме\n"
                "    самого резолвера. Переключи апстрим на DoH или рекурсию.")
        elif not dget(res, "recursion").get("ok"):
            problems.append(
                "Рекурсия не работает: случайные имена не резолвятся.\n"
                "    Резолвер отдаёт только кэш. Проверь выход с сервера на :53.")
        elif yt.get("ok") and yt.get("ips"):
            notes.append("Резолвер здоров, рекурсия работает, youtube отдаётся.")
        if not dget(res, "tcp").get("ok"):
            problems.append(
                "TCP:53 на резолвере недоступен. Нужен для длинных ответов\n"
                "    и DNSSEC. Открой его на туннельном интерфейсе.")

    # Если наружу не прошло НИЧЕГО, отличить фильтрацию в ДЦ от полного
    # отсутствия связи невозможно. Обвинять хостинг в такой ситуации —
    # та же ошибка, что читать пустой результат как «чисто».
    egress_any = any(isinstance(v, dict) and v.get("ok")
                     for k, v in eg.items()
                     if k not in ("trusted_ip", "test_ip"))
    if eg and not egress_any:
        problems.append(
            "С сервера наружу не прошла НИ ОДНА проверка: ни DNS, ни TLS,\n"
            "    ни QUIC. Это не диагноз фильтрации, а отсутствие связи —\n"
            "    проверь сеть на самом VPS, маршрут по умолчанию и хостера.")
    elif eg:
        if not any(isinstance(v, dict) and v.get("ok")
                   for k, v in eg.items() if str(k).startswith("udp53")):
            problems.append(
                "С самого сервера UDP:53 наружу не проходит. Рекурсия работать\n"
                "    не сможет. Проверь исходящие правила и политику хостера.")
        t = dget(eg, "tls")
        if not t.get("ok") and eg.get("trusted_ip", True) and egress_any:
            problems.append(
                "С сервера TLS с именем youtube не проходит ({}).\n"
                "    Значит фильтрация уже на стороне ДЦ, а не только у клиента.\n"
                "    Туннель тут не поможет — нужна другая локация."
                .format(t.get("verdict")))
        elif not t.get("ok"):
            notes.append(
                "TLS-проверка не проведена: достоверный IP получить не удалось,\n"
                "    а запасные адреса не отвечают. Вывод о фильтрации не делается.")
        else:
            notes.append("Путь сервер -> Google чист: TLS с youtube проходит.")
        if not dget(eg, "quic").get("ok") and eg.get("trusted_ip", True):
            notes.append("QUIC с сервера не проходит — не критично, но видео будет"
                         "\n    идти только по TCP.")

    fwv = dget(RESULT, "firewall", "forward")
    if fwv.get("v4") and fwv["v4"] != "1":
        problems.append(
            "ip_forward выключена. Сервер не пересылает пакеты клиентов —\n"
            "    туннель поднимется, но интернета за ним не будет.\n"
            "    sysctl -w net.ipv4.ip_forward=1 и в /etc/sysctl.conf")

    ctk = dget(RESULT, "firewall", "conntrack")
    if ctk.get("pct", 0) > 80:
        problems.append(
            "Таблица соединений заполнена на {}%. При переполнении сессии\n"
            "    рвутся сами по себе, и это легко принять за блокировку."
            .format(ctk["pct"]))

    for name, mtu in [x for x in dlist(dget(RESULT, "firewall"), "tunnels")
                      if isinstance(x, (list, tuple)) and len(x) == 2]:
        if mtu and mtu > 1420:
            notes.append(
                "MTU интерфейса {} равен {}. Если клиенты жалуются на\n"
                "    подвисающие страницы при живом пинге — опусти до 1280."
                .format(name, mtu))

    if not problems:
        print("  Сервер здоров. Проблема, если она есть, на стороне клиента.")
    else:
        for p in problems:
            print("  * " + p)
    if notes:
        print()
        for n in notes:
            print("  - " + n)

    RESULT["verdict"] = {"problems": problems, "notes": notes}


def mode_server(args):
    print("netprobe v{} — режим СЕРВЕР".format(VERSION))
    print("{} / Python {}".format(platform.platform(), platform.python_version()))
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("ВНИМАНИЕ: без root часть данных (ss -p, iptables) будет пустой.")
    RESULT["mode"] = "server"
    RESULT["time"] = time.strftime("%Y-%m-%d %H:%M:%S")

    wildcard, _ = stage("слушатели", server_listeners)
    res, _ = stage("резолвер", server_resolver, args.dns)
    eg, _ = stage("выход наружу", server_egress)
    stage("файрвол", server_firewall)
    stage("вердикт", server_verdict, wildcard, res, eg)


# ==========================================================================
# Самопроверка
# ==========================================================================

def _mock_dns_server(ips, delay_second=None, second_ips=None):
    """Поднимает локальный DNS-сервер на случайном порту для самопроверки."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    def build(tid, q, addrs):
        an = b"".join(b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) +
                      bytes(int(x) for x in a.split("."))
                      for a in addrs)
        return tid + struct.pack(">HHHHH", 0x8180, 1, len(addrs), 0, 0) + q + an

    def responder():
        try:
            data, addr = srv.recvfrom(4096)
            tid, q = data[:2], data[12:]
            srv.sendto(build(tid, q, ips), addr)
            if delay_second is not None:
                time.sleep(delay_second)
                srv.sendto(build(tid, q, second_ips or ips), addr)
        except Exception:
            pass

    threading.Thread(target=responder, daemon=True).start()
    return srv, port


def selftest():
    """Проверка самого скрипта, без внешней сети.

    Нужна там, где поведение системы неизвестно: Windows, Termux, урезанные
    сборки Python. Показывает, работает ли машинерия, ПРЕЖДЕ чем доверять
    её выводам о блокировках.
    """
    section("САМОПРОВЕРКА netprobe v{}".format(VERSION))
    print("  {} / Python {}".format(platform.platform(),
                                    platform.python_version()))
    print()
    ok, bad = 0, []

    limits = []

    def t(name, cond, detail="", env=False):
        """env=True — не сбой скрипта, а ограничение системы."""
        nonlocal ok
        if cond:
            ok += 1
            line(name, "норма")
        elif env:
            limits.append(name)
            line(name, "недоступно" + (" — " + str(detail) if detail else ""))
        else:
            bad.append(name)
            line(name, "СБОЙ" + (" — " + str(detail) if detail else ""))

    # --- сборка и разбор пакетов ---
    try:
        tid, pkt = build_query("www.example.com")
        t("сборка DNS-запроса", pkt[:2] == struct.pack(">H", tid) and len(pkt) > 20)
    except Exception as e:
        t("сборка DNS-запроса", False, e)

    try:
        hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        q = b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
        a = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + bytes([1, 2, 3, 4])
        r = parse_response(hdr + q + a, 0x1234)
        t("разбор ответа (сжатие имён)", r["ips"] == ["1.2.3.4"] and r["ttls"] == [300])
    except Exception as e:
        t("разбор ответа (сжатие имён)", False, e)

    try:
        parse_response(hdr + q + a, 0x9999)
        t("защита от чужого id", False, "подмена не отклонена")
    except ValueError:
        t("защита от чужого id", True)
    except Exception as e:
        t("защита от чужого id", False, e)

    crash = None
    for bad_pkt in (b"", b"\x00" * 5, b"\xff" * 120):
        try:
            parse_response(bad_pkt, 0x1234)
        except ValueError:
            pass
        except Exception as e:
            crash = e
    t("устойчивость к мусорным пакетам", crash is None, crash)

    # --- сетевой слой на локальном сервере ---
    try:
        srv, port = _mock_dns_server(["9.9.9.9"])
        r = _dns_udp_port("127.0.0.1", port, "www.example.com")
        srv.close()
        t("UDP-запрос и приём ответа", r.get("ips") == ["9.9.9.9"], r.get("error"))
    except Exception as e:
        t("UDP-запрос и приём ответа", False, e)

    try:
        srv, port = _mock_dns_server(["10.0.0.1"], delay_second=0.2,
                                     second_ips=["142.250.1.1"])
        r = _dns_udp_port("127.0.0.1", port, "www.example.com")
        srv.close()
        t("обнаружение инъекции", classify(r)[0] == "injected", classify(r)[1])
    except Exception as e:
        t("обнаружение инъекции", False, e)

    try:
        srv, port = _mock_dns_server(["142.250.1.1"], delay_second=0.2,
                                     second_ips=["142.250.2.2"])
        r = _dns_udp_port("127.0.0.1", port, "www.example.com")
        srv.close()
        t("нет ложной инъекции при ротации", classify(r)[0] == "resolves",
          classify(r)[1])
    except Exception as e:
        t("нет ложной инъекции при ротации", False, e)

    # --- классификация ---
    cases = [({"ok": True, "ips": ["1.2.3.4"]}, "resolves"),
             ({"ok": True, "ips": [], "rcode": "NOERROR"}, "empty"),
             ({"ok": False, "error": "timeout"}, "silent"),
             ({"ok": False, "error": "[Errno 1] Operation not permitted"},
              "blocked_local"),
             ({"ok": True, "ips": ["1.2.3.4"], "suspect": True}, "forged")]
    okc = all(classify(c)[0] == exp for c, exp in cases)
    t("классификация статусов", okc)

    # --- определение туннелей ---
    t("распознавание туннелей",
      all(looks_like_tunnel(x) for x in ("awg0", "amn0", "WireGuard Tunnel",
                                         "TAP-Windows Adapter V9"))
      and not any(looks_like_tunnel(x) for x in ("eth0", "Wi-Fi", "docker0")))

    # --- системные утилиты ---
    ifs = local_interfaces()
    t("перечисление интерфейсов", bool(ifs),
      "нет ip/ipconfig — вывод про туннель будет 'не проверялось'", env=True)
    res = system_resolvers()
    t("чтение системных резолверов", bool(res), "не удалось определить", env=True)

    src = src_ip_for("8.8.8.8", 443, udp=False)
    t("определение исходящего адреса", bool(src), "маршрут не определяется")

    # --- логика сверки и вердиктов ---
    t("сверка :53 против DoH",
      cross_check({"ips": ["10.0.0.1"]}, {"ips": ["142.250.1.1"]})["suspicious"]
      and not cross_check({"ips": ["142.250.1.1"]},
                          {"ips": ["142.250.9.9"]})["suspicious"])

    t("формат всех статусов",
      all(isinstance(fmt(c), str) and fmt(c)
          for c in ({"ok": True, "ips": ["1.2.3.4"]},
                    {"ok": True, "ips": [], "rcode": "NXDOMAIN"},
                    {"ok": False, "error": "timeout"},
                    {"ok": True, "ips": ["1.2.3.4"],
                     "race": {"first": ["1.2.3.4"], "second": ["5.6.7.8"],
                              "foreign_src": None}})))

    try:
        probe = {"version": VERSION, "mode": "client",
                 "routing": {"ifaces": [("a", "1.2.3.4")]},
                 "dns": {"system": {}}, "transport": {"sni": {}}}
        json.dumps(probe, ensure_ascii=False)
        t("сериализация результата в JSON", True)
    except Exception as e:
        t("сериализация результата в JSON", False, e)

    t("восстановление старых файлов",
      was_intercepted({"dns": {"blackhole": {"ok": True}}})
      and not was_intercepted({"dns": {"blackhole": {"ok": False}}}))

    t("детектор заглушек настроен", bool(http_blockpage.__doc__))

    # --- обезличивание: ошибка здесь опаснее всех прочих ---
    probe = {"external": "203.0.113.9", "region": "Город",
             "asn": {"asn": "AS64500", "prefix": "203.0.113.0/24",
                     "country": "RU"},
             "routing": {"ifaces": [["amn0", "10.8.1.2"]]},
             "transport": {"ip": "142.250.1.1"},
             "scan": {"a.com": {"label": "Узел 10.0.0.5", "ok": False}}}
    an = anonymize(probe)
    leaked = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
                        json.dumps(an, ensure_ascii=False).replace(
                            an.get("asn", {}).get("prefix", "\x00"), ""))
    t("обезличивание убирает адреса", not leaked, leaked)
    t("обезличивание чистит пути с именем пользователя",
      "filin" not in json.dumps(anonymize(
          {"n": "/home/filin/x и C:\\Users\\Filin\\y"}), ensure_ascii=False).lower())
    t("обезличивание сохраняет ASN и регион",
      an.get("asn", {}).get("asn") == "AS64500"
      and an.get("asn", {}).get("prefix") == "203.0.113.0/24"
      and an.get("region") == "Город")

    t("устойчивость к битым файлам прогонов",
      dget({"a": "строка"}, "a", "b") == {}
      and dlist({"a": 5}, "a") == []
      and was_intercepted({"dns": "мусор"}) is False
      and flat_dns({"dns": {"resolvers": {"s": {"d": "мусор"}}}}) is not None)

    def verdicts_survive():
        """Выдаются ли вердикты по заведомо неполным данным."""
        junk = {"system": "x", "resolvers": [1], "doh": None, "nxdomain": 2,
                "cross_check": "c", "dnssec": [1], "big_udp": "d",
                "injected": "e", "blackhole": "f"}
        buf = io.StringIO()
        try:
            RESULT["transport"] = "мусор"
            RESULT["routing"] = {}
            RESULT["firewall"] = "мусор"
            with contextlib.redirect_stdout(buf):
                client_verdict(True, True, True, junk, {},
                               {"ok": True}, {"ok": True}, {})
                server_verdict(False, "x", "y")
        except Exception:
            return False
        finally:
            RESULT.pop("transport", None)
            RESULT.pop("firewall", None)
        return True

    t("вердикты выдаются по неполным данным", verdicts_survive())

    t("выбор тестового узла устойчив",
      all(isinstance(pick_ip(x), tuple) for x in
          ("строка", [1], {}, {"doh": "x"}, {"doh": {"a": "мусор"}},
           {"doh": {"a": {"ok": True, "ips": "не-список"}}},
           {"resolvers": {"s": "мусор"}}))
      and pick_ip({"doh": {"a": {"ok": True,
                                 "ips": [None, 5, "мусор", "8.8.4.4"]}}})[0]
      == "8.8.4.4")

    def no_data_distinguished():
        """«Ничего не измерилось» не должно читаться как «всё чисто»."""
        dead = {"system": {"y": {"ok": False, "error": "timeout"}},
                "resolvers": {}, "doh": {}, "tcp53": {},
                "big_udp": {"ok": False}, "small_udp": {"ok": False}}
        buf = io.StringIO()
        RESULT["routing"] = {}
        RESULT["transport"] = {"trusted_ip": False}
        try:
            with contextlib.redirect_stdout(buf):
                client_verdict(False, False, False, dead, {},
                               {"ok": False, "error": "timeout"},
                               {"ok": False}, {})
        except Exception:
            return False
        finally:
            RESULT.pop("transport", None)
        out = buf.getvalue()
        return "ДАННЫХ НЕТ" in out and "Явных блокировок не найдено" not in out

    t("полный отказ не читается как «чисто»", no_data_distinguished())

    def server_no_data():
        """Полный отказ на сервере не должен обвинять хостинг."""
        bad = {"ok": False, "error": "timeout"}
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                server_verdict(False,
                               {"addr": "1.2.3.4", "www.youtube.com": bad,
                                "www.google.com": bad, "recursion": bad,
                                "tcp": bad},
                               {"udp53_Google": bad, "quic": bad,
                                "tls": {"ok": False, "verdict": "timeout"},
                                "trusted_ip": True})
        except Exception:
            return False
        out = buf.getvalue()
        return "отсутствие связи" in out and "другая локация" not in out

    t("отказ на сервере не винит хостинг", server_no_data())

    def digest_control():
        """Сводка не должна выдавать обрыв связи за тотальную блокировку."""
        import tempfile as _tf
        tmp = _tf.mkdtemp()
        paths = []
        for i in range(2):
            pth = os.path.join(tmp, "s{}.json".format(i))
            with open(pth, "w", encoding="utf-8") as fh:
                json.dump({"version": VERSION, "mode": "scan", "time": "t",
                           "scan": {"a.com": {"label": "A", "group": "Видео",
                                              "ok": False},
                                    "example.com": {"label": "К",
                                                    "group": "Контроль",
                                                    "ok": False}}}, fh)
            paths.append(pth)

        class _A:
            files = paths
            json = None

        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                rc = mode_digest(_A())
        except Exception:
            return False
        return rc == 1 and "НЕДОСТОВЕРНЫ" in buf.getvalue()

    t("сводка отвергает замеры без связи", digest_control())

    def stage_isolation():
        """Падение одного раздела не должно обнулять остальные."""
        RESULT.pop("errors", None)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                res, ok = stage("тест", lambda: 1 / 0)
        except Exception:
            return False
        return res is None and ok is False and bool(RESULT.get("errors"))

    t("сбой раздела не рушит прогон", stage_isolation())

    def atomic_write():
        """Оборванная запись не должна портить прежний файл."""
        import tempfile as _tf
        tmpdir = _tf.mkdtemp()
        target = os.path.join(tmpdir, "r.json")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write('{"prev":1}')

        class _A:
            json = target
            anon = False

        real = json.dump

        def boom(_obj, fp, **_kw):
            fp.write('{"cut')
            raise IOError("тест")

        buf = io.StringIO()
        try:
            json.dump = boom
            with contextlib.redirect_stdout(buf):
                save_result(_A())
        finally:
            json.dump = real
        with open(target, encoding="utf-8") as fh:
            kept = fh.read() == '{"prev":1}'
        return kept and not os.path.exists(target + ".tmp")

    t("запись результата атомарна", atomic_write())
    RESULT.pop("errors", None)

    t("нет утечки дескрипторов", _fd_stable())

    t("кириллические домены (punycode)",
      to_punycode("почта.рф") == "xn--80a1acny.xn--p1ai"
      and valid_hostname(to_punycode("дом.рф"))
      and to_punycode("Example.COM.") == "example.com")

    t("проверка доменных имён",
      all(valid_hostname(h) for h in ("a.com", "www.youtube.com",
                                      "rr1---sn-4g5e6nzs.googlevideo.com"))
      and not any(valid_hostname(h) for h in ("../etc/passwd", "a.com:99",
                                              "a_b.com", "", "a..b.com")))

    t("встроенные списки корректны",
      all(valid_hostname(h) for _, items in SCAN_GROUPS for h, _ in items)
      and all(valid_hostname(h) for h, _ in SCOPE_SNI))

    t("длинные значения не ломают вёрстку", _line_len_ok())

    t("разбор TXT-записи",
      parse_txt(struct.pack(">HHHHHH", 0x77, 0x8180, 0, 1, 0, 0) +
                b"\x00" + struct.pack(">HHIH", 16, 1, 60, 6) +
                b"\x0512345", 0x77) == ["12345"])

    # --- вывод ---
    t("кодировка вывода (тире, кириллица)", _encoding_ok())

    print()
    total = ok + len(bad) + len(limits)
    line("итог", "{} из {} пройдено".format(ok, total))
    if bad:
        print()
        sub("СБОИ: " + ", ".join(bad))
        sub("Это ошибки самого скрипта. Выводам, зависящим от них,")
        sub("доверять нельзя — пришли этот вывод целиком.")
    if limits:
        print()
        sub("Ограничения системы: " + ", ".join(limits))
        sub("Не сбой скрипта: соответствующие строки будут помечены")
        sub("как 'не проверялось', остальные проверки достоверны.")
    if not bad and not limits:
        sub("Всё исправно — выводам о блокировках можно доверять.")
    return 0 if not bad else 1


def _same_nets(a, b):
    """Пересекаются ли наборы адресов хотя бы по сети /16."""
    def nets(ips):
        return {".".join(i.split(".")[:2]) for i in ips if ":" not in i}
    na, nb = nets(a), nets(b)
    if not na or not nb:
        return True
    return bool(na & nb)


def _dns_udp_port(server, port, name):
    """dns_udp на нестандартный порт — только для самопроверки."""
    tid, pkt = build_query(name)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    try:
        s.sendto(pkt, (server, port))
        buf, _ = s.recvfrom(65535)
        r = parse_response(buf, tid)
        r["ok"] = True
        s.settimeout(0.7)
        try:
            buf2, _src = s.recvfrom(65535)
            second = parse_response(buf2, tid)
            a, b = set(r.get("ips") or []), set(second.get("ips") or [])
            if b and a and not _same_nets(a, b):
                r["race"] = {"first": sorted(a), "second": sorted(b),
                             "foreign_src": None}
        except Exception:
            pass
        return r
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        s.close()


def _line_len_ok():
    """Обрезаются ли поля из чужих файлов при выводе."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            line("к" * 200, "з" * 400)
            sub("п" * 400)
            section("р" * 200)
    except Exception:
        return False
    return max((len(x) for x in buf.getvalue().splitlines()), default=0) <= 130


def _fd_stable():
    """Закрываются ли сокеты. Утечка проявляется только на длинных
    прогонах, когда файловые дескрипторы кончаются посреди работы."""
    if not os.path.isdir("/proc/self/fd"):
        return True
    try:
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(12):
            tcp_probe("127.0.0.1", 9, timeout=0.2)
            tls_probe("127.0.0.1", "a.com", port=9, timeout=0.2)
            quic_probe("127.0.0.1", port=9, timeout=0.2)
        after = len(os.listdir("/proc/self/fd"))
        return after - before <= 2
    except Exception:
        return True


def _encoding_ok():
    """Переживёт ли вывод текущую кодировку консоли."""
    probe = "резолвит — 1.2.3.4 <-> тест"
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        probe.encode(enc)
        return True
    except Exception:
        return False


# ==========================================================================
# Сравнение прогонов
# ==========================================================================

def dget(obj, *keys):
    """Безопасный доступ во вложенный словарь.

    Файлы прогонов могут прийти от другого человека, из другой версии
    или просто повреждёнными. Тип поля не гарантирован, поэтому любой
    промах по типу даёт пустой словарь, а не падение всего разбора.
    """
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return {}
        cur = cur.get(k)
    return cur if isinstance(cur, dict) else {}


def dlist(obj, *keys):
    """То же для полей-списков."""
    cur = obj
    for k in keys:
        if not isinstance(cur, dict):
            return []
        cur = cur.get(k)
    return cur if isinstance(cur, list) else []


def was_intercepted(run_data):
    """Был ли в прогоне перехват :53, включая файлы прежних версий.

    До версии 3 признак не сохранялся отдельно — его приходится
    восстанавливать по результату пробы в пустоту."""
    d = dget(run_data, "dns")
    if "intercepted" in d:
        return bool(d["intercepted"])
    if dget(d, "blackhole").get("ok"):
        return True
    return any(isinstance(r, dict) and r.get("ok")
               for r in dget(d, "blackhole_all").values())


def flat_dns(run_data):
    """Свести все DNS-проверки прогона к статусам (источник, домен) -> код."""
    out = {}
    d = dget(run_data, "dns")
    forged = was_intercepted(run_data)
    for dom, r in dget(d, "system").items():
        out[("системный", dom)] = classify(r if isinstance(r, dict) else None)[0]
    for srv, res in dget(d, "resolvers").items():
        if not isinstance(res, dict):
            continue
        for dom, r in res.items():
            if not isinstance(r, dict):
                out[(srv, dom)] = "n/a"
                continue
            # В файлах прежних версий пометки suspect нет — восстанавливаем
            # её по факту перехвата, иначе подделка читается как успех.
            if forged and r.get("ok") and not r.get("suspect"):
                r = dict(r, suspect=True)
            out[(srv, dom)] = classify(r)[0]
    for name, r in dget(d, "doh").items():
        out[("DoH " + name, "www.youtube.com")] = classify(
            r if isinstance(r, dict) else None)[0]
    return out


STATUS_WORD = {
    "resolves": "резолвит",
    "empty": "не резолвит",
    "silent": "молчит",
    "noroute": "нет маршрута",
    "blocked_local": "запрещено локально",
    "resolver_down": "резолвер недоступен",
    "nxdomain_sys": "имя не разрешается",
    "refused": "отклонено",
    "rst": "сброс",
    "forged": "ПОДМЕНА",
    "injected": "ИНЪЕКЦИЯ",
    "fail": "ошибка",
    "n/a": "не проверялось",
}


def word(code):
    return STATUS_WORD.get(code, code or "не проверялось")


def mode_digest(args):
    """Сводка по нескольким выпускам scan — «подшивка».

    Один замер показывает, что режется у тебя. Пачка замеров показывает,
    где фильтр общий для страны, а где он местный, у конкретной сети.
    Именно это и невозможно увидеть из одного файла.
    """
    runs = []
    for path in args.files:
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception as e:
            print("Пропущен {}: {}".format(path, e))
            continue
        if d.get("mode") != "scan" or not d.get("scan"):
            print("Пропущен {}: это не выпуск scan".format(path))
            continue
        runs.append((path, d))

    if not runs:
        print("Нет пригодных выпусков. Нужны файлы, снятые режимом scan.")
        return 1

    section("СВОДКА ПО {} ВЫПУСКАМ".format(len(runs)))
    for path, d in runs:
        # Поля приходят из чужих файлов: тип не гарантирован.
        a = d.get("asn")
        a = a if isinstance(a, dict) else {}
        when = str(d.get("time") or "")[:10] or "дата н/д"
        line(os.path.basename(path)[:34],
             "{} | {} | {}".format(str(d.get("region") or "регион не указан"),
                                   str(a.get("asn") or "ASN н/д"), when))

    # Собираем по каждому имени: где прошло, где срезано.
    stats = {}
    skipped = 0
    for _, d in runs:
        entries = d.get("scan")
        if not isinstance(entries, dict):
            skipped += 1
            continue
        for host, v in entries.items():
            # Файлы приходят из чужих рук: одна кривая запись не должна
            # ронять сводку по всем остальным выпускам.
            if not isinstance(v, dict):
                skipped += 1
                continue
            e = stats.setdefault(host, {"label": str(v.get("label", host)),
                                        "group": str(v.get("group", "")),
                                        "ok": 0, "blocked": 0, "where": []})
            if v.get("ok"):
                e["ok"] += 1
            else:
                e["blocked"] += 1
                asn_d = d.get("asn")
                asn_d = asn_d if isinstance(asn_d, dict) else {}
                tag = str(d.get("region") or asn_d.get("asn") or "?")[:24]
                if tag not in e["where"]:
                    e["where"].append(tag)

    if skipped:
        print()
        sub("Пропущено повреждённых записей: {}.".format(skipped))

    if not stats:
        print()
        sub("Пригодных записей не осталось — все выпуски повреждены.")
        return 1

    total = len(runs)
    everywhere = [e for e in stats.values() if e["blocked"] == total]
    somewhere = [e for e in stats.values()
                 if 0 < e["blocked"] < total]
    nowhere = [e for e in stats.values() if e["blocked"] == 0]

    # Контрольная группа в сводке важнее, чем в одиночном прогоне: если
    # у всех участников упал сам канал, «режется везде» покажет тотальную
    # блокировку там, где на деле просто не было связи.
    # Считаем ПО ВЫПУСКАМ, а не по именам: важно, у скольких участников
    # не было связи, а не сколько контрольных имён где-то не прошло.
    with_ctrl, bad_runs = 0, []
    for path, d in runs:
        entries = d.get("scan")
        if not isinstance(entries, dict):
            continue
        ctrl_items = [v for v in entries.values()
                      if isinstance(v, dict) and "Контроль" in str(v.get("group", ""))]
        if not ctrl_items:
            continue
        with_ctrl += 1
        if not any(v.get("ok") for v in ctrl_items):
            bad_runs.append(os.path.basename(path))
    ctrl_bad = bad_runs
    if with_ctrl and len(bad_runs) == with_ctrl:
        section("ДАННЫЕ НЕДОСТОВЕРНЫ")
        sub("Контрольные имена не прошли НИ В ОДНОМ выпуске.")
        sub("Значит у участников не было связи, а не тотальная блокировка.")
        sub("Сводку по таким выпускам строить нельзя — нужны новые замеры.")
        RESULT["digest"] = {"valid": False}
        return 1
    if ctrl_bad:
        print()
        sub("В {} из {} выпусков не прошли контрольные имена ({}) —"
            .format(len(ctrl_bad), with_ctrl, ", ".join(ctrl_bad[:3])))
        sub("эти замеры могли быть сняты при обрыве связи и завышают")
        sub("долю блокировок. Стоит их переснять.")

    section("РЕЖЕТСЯ ВЕЗДЕ ({} из {})".format(len(everywhere), len(stats)))
    if total == 1:
        sub("ВНИМАНИЕ: выпуск всего один, «везде» здесь означает «в этом")
        sub("единственном замере». Смысл сводка приобретает от трёх и более.")
        print()
    if everywhere:
        sub("Общая политика: фильтр действует во всех замерах.")
        print()
        for e in sorted(everywhere, key=lambda x: x["group"]):
            line(e["label"][:34], e["group"][:30])
    else:
        sub("(нет имён, заблокированных во всех выпусках)")

    section("РЕЖЕТСЯ МЕСТАМИ ({})".format(len(somewhere)))
    if somewhere:
        sub("Фильтр зависит от сети или региона — самое интересное здесь.")
        print()
        for e in sorted(somewhere, key=lambda x: -x["blocked"]):
            line("{} [{}/{}]".format(e["label"][:26], e["blocked"], total),
                 ", ".join(e["where"][:3]))
    else:
        sub("(нет расхождений между выпусками)")

    section("ПРОХОДИТ ВЕЗДЕ")
    line("имён", len(nowhere))

    # Группы по доле блокировок — видно, по чему бьют прицельно.
    section("ПО ГРУППАМ")
    groups = {}
    for e in stats.values():
        g = groups.setdefault(e["group"] or "без группы", [0, 0])
        g[0] += e["blocked"]
        g[1] += e["blocked"] + e["ok"]
    for g, (b, t) in sorted(groups.items(), key=lambda x: -(x[1][0] / max(x[1][1], 1))):
        pct = 100 * b // max(t, 1)
        line(g[:38], "{}% проверок срезано".format(pct))

    if args.json:
        def src(d):
            a = d.get("asn")
            a = a if isinstance(a, dict) else {}
            return {"region": str(d.get("region") or ""),
                    "asn": str(a.get("asn") or ""),
                    "time": str(d.get("time") or "")}

        out = {"version": VERSION, "mode": "digest", "runs": len(runs),
               "time": time.strftime("%Y-%m-%d %H:%M:%S"),
               "sources": [src(d) for _, d in runs],
               "everywhere": [e["label"] for e in everywhere],
               "somewhere": [{"label": e["label"], "blocked": e["blocked"],
                              "where": e["where"]} for e in somewhere]}
        # Та же атомарная запись, что и для прогонов: сводку могли
        # собирать по десяткам файлов, терять её из-за обрыва нельзя.
        tmp = args.json + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=1)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass
            os.replace(tmp, args.json)
            print("\nСводка сохранена: {}".format(args.json))
        except Exception as e:
            print("Не удалось сохранить: {}".format(e))
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
    return 0


def mode_compare(args):
    try:
        with open(args.first, encoding="utf-8") as f:
            a = json.load(f)
        with open(args.second, encoding="utf-8") as f:
            b = json.load(f)
    except Exception as e:
        print("Не удалось прочитать файлы: {}".format(e))
        return 1

    la = a.get("label", args.first)
    lb = b.get("label", args.second)
    section("СРАВНЕНИЕ: '{}' -> '{}'".format(la, lb))

    va, vb = a.get("version"), b.get("version")
    if va != vb or (va or 0) < VERSION:
        sub("Примечание: файлы сняты разными версиями netprobe ({} и {}).".format(
            va or "?", vb or "?"))
        sub("Старые прогоны читаются с поправками, но надёжнее пересобрать оба.")
        print()

    ma, mb = a.get("mode", "?"), b.get("mode", "?")
    if ma != mb:
        sub("ВНИМАНИЕ: сравниваются разные режимы ({} и {}).".format(ma, mb))
        sub("Сравнивать имеет смысл два клиентских прогона — с VPN и без.")
        sub("Результат ниже будет почти пустым.")
        print()
    elif la == lb:
        sub("ВНИМАНИЕ: у обоих прогонов одна метка '{}'.".format(la))
        sub("Возможно, это один и тот же файл или одно и то же состояние.")
        print()

    ra, rb = dget(a, "routing"), dget(b, "routing")

    def yn(v):
        return "да" if v else ("нет" if v is not None else "не проверялось")

    line("DNS идёт через туннель", "{} -> {}".format(
        yn(ra.get("dns_in_tunnel")), yn(rb.get("dns_in_tunnel"))))
    line("HTTPS идёт через туннель", "{} -> {}".format(
        yn(ra.get("web_in_tunnel")), yn(rb.get("web_in_tunnel"))))
    line("внешний IP", "{} -> {}".format(
        dget(a, "transport", "external").get("ip") or "не определён",
        dget(b, "transport", "external").get("ip") or "не определён"))

    ia = was_intercepted(a)
    ib = was_intercepted(b)
    line("перехват порта 53", "{} -> {}".format(yn(ia), yn(ib)))
    if ia or ib:
        sub("В прогоне с перехватом ответы по открытому :53 недостоверны —")
        sub("они помечены как ПОДМЕНА и успехом не считаются.")

    # Самая частая ошибка: оба файла сняты в одном и том же состоянии.
    exa = dget(a, "transport", "external").get("ip")
    exb = dget(b, "transport", "external").get("ip")
    same_state = (ra.get("dns_in_tunnel") == rb.get("dns_in_tunnel")
                  and ra.get("web_in_tunnel") == rb.get("web_in_tunnel")
                  and bool(ra.get("tunnels")) == bool(rb.get("tunnels")))
    if same_state and ma == mb:
        print()
        sub("ВНИМАНИЕ: оба прогона сняты в ОДНОМ состоянии" +
            (" (внешний IP совпадает: {})".format(exa) if exa and exa == exb else "") +
            ".")
        sub("Для осмысленного сравнения нужен один прогон при выключенном")
        sub("VPN и один при включённом.")

    print("\n  -- DNS: что изменилось --")
    fa, fb = flat_dns(a), flat_dns(b)
    diff = 0
    for k in sorted(set(fa) | set(fb), key=lambda x: (x[0], x[1])):
        va, vb = fa.get(k), fb.get(k)
        if va != vb:
            diff += 1
            sub("{:<22} {:<26} {:<14} -> {}".format(
                k[0][:22], k[1][:26], word(va), word(vb)))
    if not diff:
        sub("(различий нет)")

    print("\n  -- TLS по имени (SNI) --")
    sa = dget(a, "transport", "sni")
    sb = dget(b, "transport", "sni")

    def sni_word(d, k):
        if k not in d:
            return "не проверялось"
        r = d[k]
        if not isinstance(r, dict):
            return "не проверялось"
        if r.get("ok"):
            return "проходит"
        return {"rst": "режется (RST)", "timeout": "режется (drop)",
                "tls-error": "ошибка TLS"}.get(r.get("verdict"), "не проходит")

    shown = 0
    for k in sorted(set(sa) | set(sb)):
        wa, wb = sni_word(sa, k), sni_word(sb, k)
        if wa != wb:
            shown += 1
            sub("{:<30} {:<16} -> {}".format(k[:30], wa, wb))
    if not shown:
        sub("(различий нет)")

    print("\n  -- вердикты --")
    for tag, run_, lbl in (("A", a, la), ("B", b, lb)):
        v = [x for x in dlist(dget(run_, "verdict"), "problems")
             if isinstance(x, str)]
        sub("{} ({}): {}".format(
            tag, lbl, "проблем не найдено" if not v else "проблем: {}".format(len(v))))
        for p in v:
            print("        - " + p.splitlines()[0])
    return 0


# ==========================================================================

def setup_output():
    """Не дать выводу упасть на старых кодировках консоли.

    В Windows при перенаправлении в файл консоль может оказаться в cp866,
    где нет длинного тире. Без этой правки прогон обрывается посреди работы
    с UnicodeEncodeError — причём тем вероятнее, чем больше нашлось проблем.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def main():
    setup_output()
    ap = argparse.ArgumentParser(
        description="netprobe v3 — диагностика блокировок (клиент и сервер)")
    subs = ap.add_subparsers(dest="mode")

    c = subs.add_parser("client", help="проверка с машины за туннелем")
    c.add_argument("--dns", help="адрес резолвера в туннеле, напр. 172.29.172.254")
    c.add_argument("--label", default="run", help="метка прогона: vpn / novpn")
    c.add_argument("--json", help="сохранить результат для сравнения")

    s = subs.add_parser("server", help="проверка на VPS")
    s.add_argument("--dns", help="адрес резолвера (иначе ищется amnezia-dns)")
    s.add_argument("--json", help="сохранить результат")

    sc = subs.add_parser("scan", help="карта фильтрации по именам (39 сайтов)")
    sc.add_argument("--list", help="свой список имён из файла")
    sc.add_argument("--label", default="scan", help="метка прогона")
    sc.add_argument("--json", help="сохранить результат")
    sc.add_argument("--anon", action="store_true",
                    help="обезличить: убрать IP, адреса и локальные данные")
    sc.add_argument("--region", help="регион для сводки, напр. \"Донецк\"")

    subs.add_parser("selftest",
                    help="проверить сам скрипт (запусти первым на новой ОС)")

    dg = subs.add_parser("digest", help="сводка по нескольким выпускам scan")
    dg.add_argument("files", nargs="+", help="файлы scan-*.json")
    dg.add_argument("--json", help="сохранить сводку")

    p = subs.add_parser("compare", help="сравнить два прогона")
    p.add_argument("first")
    p.add_argument("second")

    args = ap.parse_args()
    if not args.mode:
        ap.print_help()
        return 1

    if args.mode == "compare":
        return mode_compare(args)
    if args.mode == "selftest":
        return selftest()
    if args.mode == "digest":
        return mode_digest(args)

    t0 = time.time()
    try:
        if args.mode == "client":
            mode_client(args)
        elif args.mode == "scan":
            rc = mode_scan(args)
            if rc:
                return rc          # список не прочитан или узел недоступен
        else:
            mode_server(args)
    except KeyboardInterrupt:
        # Прогон в плохой сети идёт минуты. Собранное до прерывания
        # нужно сохранить: иначе Ctrl+C обнуляет всю работу.
        print("\nПрервано на {} секунде.".format(int(time.time() - t0)))
        RESULT["interrupted"] = True
        save_result(args, " (неполный: прогон прерван)")
        return 130
    except Exception as e:
        print("\nНеожиданная ошибка: {}: {}".format(type(e).__name__, e))
        RESULT.setdefault("errors", []).append(
            {"stage": "верхний уровень", "error": type(e).__name__,
             "detail": str(e)[:200]})
        save_result(args, " (неполный: прогон оборван ошибкой)")
        return 1

    print("\nГотово за {} сек.".format(int(time.time() - t0)))
    if RESULT.get("errors"):
        print("Разделов с ошибками: {} — результат неполный.".format(
            len(RESULT["errors"])))
    save_result(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
