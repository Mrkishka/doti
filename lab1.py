"""
lab1.py — криптографическая библиотека (вариант с исправленным DSA)

1. Быстрое возведение в степень по модулю.
2. Тест простоты Ферма.
3. Обобщённый алгоритм Евклида.
4. Дискретный логарифм.
5. Протокол Диффи-Хеллмана.
6. Шифр Шамира.
7. Шифр Эль-Гамаля.
8. Подпись RSA.
9. Подпись Эль-Гамаля.
10. Подпись ГОСТ Р 34.10-94.
11. Шифр RSA (шифрование файлов).
12. Шифр Вернама.
13. Подпись FIPS 186 (DSA).
"""

import random
import math
import os
import hashlib


# 1. Быстрое возведение в степень по модулю
def fast_pow(base, exp, mod):
    if mod <= 0:
        raise ValueError("Модуль должен быть положительным")
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


# 2. Тест простоты Ферма
def fermat_primality_test(n, k=5):
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if fast_pow(a, n - 1, n) != 1:
            return False
    return True


# 3. Обобщённый алгоритм Евклида
def extended_gcd(a, b):
    if a == 0 and b == 0:
        raise ValueError("НОД(0,0) не определён")
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    if old_r < 0:
        old_r = -old_r
        old_s = -old_s
        old_t = -old_t
    return old_r, old_s, old_t


# 4. Дискретный логарифм
def baby_step_giant_step(a, y, p):
    a %= p
    y %= p
    if a == 0:
        return 1 if y == 0 else None
    if y == 1:
        return 0
    m = int(math.isqrt(p)) + 1
    table = {}
    cur = 1
    for j in range(m):
        if cur not in table:
            table[cur] = j
        cur = (cur * a) % p
    gcd, inv_a, _ = extended_gcd(a, p)
    if gcd != 1:
        return None
    inv_a %= p
    inv_a_m = fast_pow(inv_a, m, p)
    cur = y
    for i in range(m + 1):
        if cur in table:
            x = i * m + table[cur]
            if fast_pow(a, x, p) == y:
                return x
        cur = (cur * inv_a_m) % p
    return None


# 5. Диффи-Хеллман
def diffie_hellman(p, g, x_a, x_b):
    y_a = fast_pow(g, x_a, p)
    y_b = fast_pow(g, x_b, p)
    k_a = fast_pow(y_b, x_a, p)
    k_b = fast_pow(y_a, x_b, p)
    assert k_a == k_b, "Ключи не совпали!"
    return {"p": p, "g": g, "x_a": x_a, "x_b": x_b,
            "y_a": y_a, "y_b": y_b, "shared_key": k_a}


def generate_diffie_hellman_instance(bits=16):
    while True:
        p = random.getrandbits(bits)
        if p < 5 or p % 2 == 0:
            continue
        if fermat_primality_test(p):
            break

    def factorize(n):
        factors = set()
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.add(d)
                n //= d
            d += 1
        if n > 1:
            factors.add(n)
        return factors

    phi = p - 1
    factors = factorize(phi)

    def is_primitive_root(g):
        if math.gcd(g, p) != 1:
            return False
        for f in factors:
            if fast_pow(g, phi // f, p) == 1:
                return False
        return True

    g = 2
    while not is_primitive_root(g):
        g += 1

    x_a = random.randint(2, p - 2)
    x_b = random.randint(2, p - 2)
    return p, g, x_a, x_b


# 6. Шифр Шамира
def shamir_generate_keys(p):
    while True:
        c = random.randint(2, p - 2)
        gcd, d, _ = extended_gcd(c, p - 1)
        if gcd == 1:
            d %= (p - 1)
            if d < 0:
                d += (p - 1)
            return c, d


def _shamir_encrypt_block(m, c, p):
    return fast_pow(m, c, p)


def _shamir_decrypt_block(c_blk, d, p):
    return fast_pow(c_blk, d, p)


def shamir_encrypt_file(input_path, output_path, p, c_a, c_b, mode="all"):
    with open(input_path, "rb") as f:
        data = f.read()
    if mode == "a":
        result = bytes(_shamir_encrypt_block(b, c_a, p) for b in data)
    elif mode == "b":
        result = bytes(_shamir_encrypt_block(b, c_b, p) for b in data)
    else:
        raise ValueError("Неизвестный режим")
    with open(output_path, "wb") as f:
        f.write(result)


def shamir_decrypt_file(input_path, output_path, p, d):
    with open(input_path, "rb") as f:
        data = f.read()
    result = bytes(_shamir_decrypt_block(b, d, p) for b in data)
    with open(output_path, "wb") as f:
        f.write(result)


def shamir_full_cycle(input_path, output_path, p, c_a, d_a, c_b, d_b):
    with open(input_path, "rb") as f:
        data = f.read()
    step1 = bytes(_shamir_encrypt_block(b, c_a, p) for b in data)
    step2 = bytes(_shamir_encrypt_block(b, c_b, p) for b in step1)
    step3 = bytes(_shamir_decrypt_block(b, d_a, p) for b in step2)
    step4 = bytes(_shamir_decrypt_block(b, d_b, p) for b in step3)
    with open(output_path, "wb") as f:
        f.write(step4)


# 7. Шифр Эль-Гамаля
def elgamal_generate_keys(p, g):
    c = random.randint(2, p - 2)
    d = fast_pow(g, c, p)
    return c, d


def elgamal_generate_instance(bits=16):
    while True:
        p = random.getrandbits(bits)
        if p < 257 or p % 2 == 0:
            continue
        if fermat_primality_test(p):
            break

    def factorize(n):
        factors = set()
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.add(d)
                n //= d
            d += 1
        if n > 1:
            factors.add(n)
        return factors

    phi = p - 1
    factors = factorize(phi)

    def is_primitive_root(g):
        if math.gcd(g, p) != 1:
            return False
        for f in factors:
            if fast_pow(g, phi // f, p) == 1:
                return False
        return True

    g = 2
    while not is_primitive_root(g):
        g += 1

    c, d = elgamal_generate_keys(p, g)
    return p, g, c, d


def elgamal_encrypt_file(input_path, output_path, p, g, d):
    with open(input_path, "rb") as f:
        data = f.read()
    output = bytearray()
    for m in data:
        k = random.randint(2, p - 2)
        a = fast_pow(g, k, p)
        b = (m * fast_pow(d, k, p)) % p
        output += a.to_bytes(4, "big")
        output += b.to_bytes(4, "big")
    with open(output_path, "wb") as f:
        f.write(output)


def elgamal_decrypt_file(input_path, output_path, p, c):
    with open(input_path, "rb") as f:
        data = f.read()
    if len(data) % 8 != 0:
        raise ValueError("Некорректный формат")
    output = bytearray()
    for i in range(0, len(data), 8):
        a = int.from_bytes(data[i:i+4], "big")
        b = int.from_bytes(data[i+4:i+8], "big")
        a_c = fast_pow(a, c, p)
        gcd, inv, _ = extended_gcd(a_c, p)
        if gcd != 1:
            raise ValueError("Нет обратного")
        inv %= p
        m = (b * inv) % p
        if m > 255:
            raise ValueError(f"Байт вне диапазона: {m}")
        output.append(m)
    with open(output_path, "wb") as f:
        f.write(output)


# Вспомогательные
def _random_prime(bits=16):
    while True:
        candidate = random.getrandbits(bits)
        if candidate < 3:
            continue
        if candidate % 2 == 0:
            candidate += 1
        if fermat_primality_test(candidate):
            return candidate


def _hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.digest()


# 8. Подпись RSA
def rsa_generate_keys(bits=16):
    p = _random_prime(bits)
    q = _random_prime(bits)
    while p == q:
        q = _random_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if e >= phi:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    else:
        while math.gcd(e, phi) != 1:
            e += 2
    _, d, _ = extended_gcd(e, phi)
    d %= phi
    if d < 0:
        d += phi
    return e, n, d


def rsa_sign_file(input_path, sig_path, n, d):
    digest = _hash_file(input_path)
    sig = bytearray()
    for b in digest:
        s = fast_pow(b, d, n)
        sig += s.to_bytes(4, "big")
    with open(sig_path, "wb") as f:
        f.write(sig)


def rsa_verify_file(input_path, sig_path, n, e):
    digest = _hash_file(input_path)
    with open(sig_path, "rb") as f:
        sig = f.read()
    if len(sig) != len(digest) * 4:
        return False
    for i, b in enumerate(digest):
        s = int.from_bytes(sig[i*4:(i+1)*4], "big")
        if fast_pow(s, e, n) != b:
            return False
    return True


# 9. Подпись Эль-Гамаля
def elgamal_sign_generate_keys(p, g):
    x = random.randint(2, p - 2)
    y = fast_pow(g, x, p)
    return x, y


def elgamal_sign_generate_params(bits=16):
    while True:
        p = random.getrandbits(bits)
        if p < 257 or p % 2 == 0:
            continue
        if fermat_primality_test(p):
            break

    def factorize(n):
        factors = set()
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.add(d)
                n //= d
            d += 1
        if n > 1:
            factors.add(n)
        return factors

    phi = p - 1
    factors = factorize(phi)

    def is_primitive_root(g):
        if math.gcd(g, p) != 1:
            return False
        for f in factors:
            if fast_pow(g, phi // f, p) == 1:
                return False
        return True

    g = 2
    while not is_primitive_root(g):
        g += 1

    x, y = elgamal_sign_generate_keys(p, g)
    return p, g, x, y


def elgamal_sign_file(input_path, sig_path, p, g, x):
    digest = _hash_file(input_path)
    sig = bytearray()
    for m in digest:
        while True:
            k = random.randint(2, p - 2)
            if math.gcd(k, p - 1) != 1:
                continue
            r = fast_pow(g, k, p)
            _, k_inv, _ = extended_gcd(k, p - 1)
            k_inv %= (p - 1)
            s = ((m - x * r) * k_inv) % (p - 1)
            if s != 0:
                break
        sig += r.to_bytes(4, "big")
        sig += s.to_bytes(4, "big")
    with open(sig_path, "wb") as f:
        f.write(sig)


def elgamal_verify_file(input_path, sig_path, p, g, y):
    digest = _hash_file(input_path)
    with open(sig_path, "rb") as f:
        sig = f.read()
    if len(sig) != len(digest) * 8:
        return False
    for i, m in enumerate(digest):
        r = int.from_bytes(sig[i*8:i*8+4], "big")
        s = int.from_bytes(sig[i*8+4:i*8+8], "big")
        if not (0 < r < p) or not (0 < s < p - 1):
            return False
        lhs = (fast_pow(y, r, p) * fast_pow(r, s, p)) % p
        if lhs != fast_pow(g, m, p):
            return False
    return True


# 10. Подпись ГОСТ Р 34.10-94
def gost_generate_params(bits_q=16):
    q = _random_prime(bits_q)
    k = 2
    while True:
        p = k * q + 1
        if fermat_primality_test(p):
            break
        k += 1
    while True:
        g = random.randint(2, p - 2)
        a = fast_pow(g, (p - 1) // q, p)
        if a != 1:
            break
    x = random.randint(1, q - 1)
    y = fast_pow(a, x, p)
    return p, q, a, x, y


def gost_sign_file(input_path, sig_path, p, q, a, x):
    digest = _hash_file(input_path)
    sig = bytearray()
    for m in digest:
        m_val = m if m != 0 else 1
        while True:
            k = random.randint(1, q - 1)
            r = fast_pow(a, k, p) % q
            if r == 0:
                continue
            s = (x * r + k * m_val) % q
            if s != 0:
                break
        sig += r.to_bytes(4, "big")
        sig += s.to_bytes(4, "big")
    with open(sig_path, "wb") as f:
        f.write(sig)


def gost_verify_file(input_path, sig_path, p, q, a, y):
    digest = _hash_file(input_path)
    with open(sig_path, "rb") as f:
        sig = f.read()
    if len(sig) != len(digest) * 8:
        return False
    for i, m in enumerate(digest):
        m_val = m if m != 0 else 1
        r = int.from_bytes(sig[i*8:i*8+4], "big")
        s = int.from_bytes(sig[i*8+4:i*8+8], "big")
        if not (0 < r < q) or not (0 < s < q):
            return False
        _, v, _ = extended_gcd(m_val, q)
        v %= q
        z1 = (s * v) % q
        z2 = ((q - r) * v) % q
        u = (fast_pow(a, z1, p) * fast_pow(y, z2, p)) % p % q
        if u != r:
            return False
    return True


# 11. Шифр RSA
def rsa_generate_keys_enc(bits=16):
    p = _random_prime(bits)
    q = _random_prime(bits)
    while p == q:
        q = _random_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if e >= phi or math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    _, d, _ = extended_gcd(e, phi)
    d %= phi
    if d < 0:
        d += phi
    return p, q, e, n, d


def rsa_encrypt_file_enc(input_path, output_path, e, n):
    with open(input_path, "rb") as f:
        data = f.read()
    output = bytearray()
    for m in data:
        output += fast_pow(m, e, n).to_bytes(4, "big")
    with open(output_path, "wb") as f:
        f.write(output)


def rsa_decrypt_file_enc(input_path, output_path, d, n):
    with open(input_path, "rb") as f:
        data = f.read()
    if len(data) % 4 != 0:
        raise ValueError("Некорректный формат")
    output = bytearray()
    for i in range(0, len(data), 4):
        c = int.from_bytes(data[i:i+4], "big")
        m = fast_pow(c, d, n)
        if m > 255:
            raise ValueError(f"Байт вне диапазона: {m}")
        output.append(m)
    with open(output_path, "wb") as f:
        f.write(output)


# 12. Шифр Вернама
def vernam_encrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        data = f.read()
    if len(key) < len(data):
        raise ValueError("Ключ короче файла!")
    with open(output_path, "wb") as f:
        f.write(bytes(m ^ k for m, k in zip(data, key)))


def vernam_decrypt_file(input_path, output_path, key):
    with open(input_path, "rb") as f:
        data = f.read()
    if len(key) < len(data):
        raise ValueError("Ключ короче файла!")
    with open(output_path, "wb") as f:
        f.write(bytes(c ^ k for c, k in zip(data, key)))


def vernam_generate_key_via_dh(input_path, bits=16):
    file_size = os.path.getsize(input_path)
    p, g, x_a, x_b = generate_diffie_hellman_instance(bits)
    res = diffie_hellman(p, g, x_a, x_b)
    shared = res["shared_key"]
    key = bytearray()
    counter = 0
    while len(key) < file_size:
        key += hashlib.sha256(f"{shared}:{counter}".encode()).digest()
        counter += 1
    return bytes(key[:file_size]), res


def vernam_generate_key_from_shared(shared, length):
    key = bytearray()
    counter = 0
    while len(key) < length:
        key += hashlib.sha256(f"{shared}:{counter}".encode()).digest()
        counter += 1
    return bytes(key[:length])


# ======================================================================
# 13. DSA (FIPS 186) — ИСПРАВЛЕННАЯ генерация параметров
# ======================================================================
def dsa_generate_params(L=32, N=16):
    """
    Генерирует параметры DSA (p, q, g):
      q — простое битности N (нечётное),
      p — простое битности L, p = k*q + 1,
      g — элемент порядка q по модулю p.

    Ключевой момент: q нечётное ⇒ для того чтобы p = k*q + 1 было
    нечётным (а значит, могло быть простым), k должно быть ЧЁТНЫМ.
    """
    # 1. Простое q битности N
    while True:
        q = random.getrandbits(N)
        q |= (1 << (N - 1)) | 1
        if fermat_primality_test(q):
            break

    # 2. Простое p = k*q + 1 битности L
    while True:
        low_k = ((1 << (L - 1)) - 1) // q + 1
        high_k = ((1 << L) - 1) // q

        if low_k > high_k:
            # q слишком велико для L бит — генерируем q поменьше
            while True:
                q = random.getrandbits(N - 1) | (1 << (N - 2)) | 1
                if fermat_primality_test(q):
                    break
            continue

        # k должно быть ЧЁТНЫМ: q нечётное, k*q должно быть чётным,
        # чтобы p = k*q + 1 было нечётным и могло быть простым
        low_k_even = low_k if low_k % 2 == 0 else low_k + 1
        high_k_even = high_k if high_k % 2 == 0 else high_k - 1

        if low_k_even > high_k_even:
            # в диапазоне нет чётного k — генерируем q поменьше
            while True:
                q = random.getrandbits(N - 1) | (1 << (N - 2)) | 1
                if fermat_primality_test(q):
                    break
            continue

        k = random.randint(low_k_even // 2, high_k_even // 2) * 2
        p = k * q + 1

        if p.bit_length() == L and fermat_primality_test(p):
            break

    # 3. g — элемент порядка q по модулю p
    while True:
        h = random.randint(2, p - 2)
        g = fast_pow(h, (p - 1) // q, p)
        if g > 1:
            break

    return p, q, g


def dsa_generate_keys(p, q, g):
    x = random.randint(1, q - 1)
    y = fast_pow(g, x, p)
    return x, y


def dsa_sign_file(input_path, sig_path, p, q, g, x):
    digest = _hash_file(input_path)
    sig = bytearray()
    for h in digest:
        h_val = h if h != 0 else 1
        while True:
            k = random.randint(1, q - 1)
            r = fast_pow(g, k, p) % q
            if r == 0:
                continue
            _, k_inv, _ = extended_gcd(k, q)
            k_inv %= q
            s = (k_inv * (h_val + x * r)) % q
            if s != 0:
                break
        sig += r.to_bytes(4, "big")
        sig += s.to_bytes(4, "big")
    with open(sig_path, "wb") as f:
        f.write(sig)


def dsa_verify_file(input_path, sig_path, p, q, g, y):
    digest = _hash_file(input_path)
    with open(sig_path, "rb") as f:
        sig = f.read()
    if len(sig) != len(digest) * 8:
        return False
    for i, h in enumerate(digest):
        h_val = h if h != 0 else 1
        r = int.from_bytes(sig[i*8:i*8+4], "big")
        s = int.from_bytes(sig[i*8+4:i*8+8], "big")
        if not (0 < r < q) or not (0 < s < q):
            return False
        _, w, _ = extended_gcd(s, q)
        w %= q
        u1 = (h_val * w) % q
        u2 = (r * w) % q
        v = ((fast_pow(g, u1, p) * fast_pow(y, u2, p)) % p) % q
        if v != r:
            return False
    return True


# ----------------------------------------------------------------------
# Вспомогательные функции ввода
# ----------------------------------------------------------------------
def input_pair(prompt="Введите два целых числа через пробел: "):
    while True:
        try:
            a_str, b_str = input(prompt).split()
            return int(a_str), int(b_str)
        except (ValueError, IndexError):
            print("Ошибка ввода. Попробуйте ещё раз.")


def generate_random_pair(bits=16):
    a = random.getrandbits(bits)
    b = random.getrandbits(bits)
    if random.choice([True, False]):
        a = -a
    if random.choice([True, False]):
        b = -b
    return a, b


def generate_prime_pair(bits=16):
    return _random_prime(bits), _random_prime(bits)


def generate_dlp_instance(bits=16):
    while True:
        p = random.getrandbits(bits)
        if p < 5 or p % 2 == 0:
            continue
        if fermat_primality_test(p):
            break
    a = random.randint(2, p - 2)
    x = random.randint(1, p - 2)
    return a, fast_pow(a, x, p), p, x


# ----------------------------------------------------------------------
# Меню
# ----------------------------------------------------------------------
def main():
    print("Криптографическая библиотека")
    print("1. Быстрое возведение в степень по модулю")
    print("2. Тест простоты Ферма")
    print("3. Обобщённый алгоритм Евклида")
    print("4. Дискретный логарифм")
    print("5. Протокол Диффи-Хеллмана")
    print("6. Шифр Шамира")
    print("7. Шифр Эль-Гамаля")
    print("8. Подпись RSA")
    print("9. Подпись Эль-Гамаля")
    print("10. Подпись ГОСТ Р 34.10-94")
    print("11. Шифр RSA (шифрование файлов)")
    print("12. Шифр Вернама (шифрование файлов)")
    print("13. Подпись FIPS 186 (DSA)")
    choice = input("Ваш выбор (1-13): ").strip()

    if choice == "1":
        print("1. Ввести вручную\n2. Сгенерировать случайно\n3. Сгенерировать простыми")
        src = input("Источник (1-3): ").strip()
        if src == "1":
            a, b = input_pair("Введите a и b: ")
            p = int(input("Модуль p = "))
        elif src == "2":
            a, b = generate_random_pair()
            p = random.getrandbits(16) + 2
            print(f"a={a}, b={b}, p={p}")
        elif src == "3":
            a, b = generate_prime_pair()
            p = random.getrandbits(16) + 2
            print(f"a={a}, b={b}, p={p}")
        else:
            return
        print(f"Результат: {fast_pow(a, b, p)}")

    elif choice == "2":
        n = int(input("Введите число: "))
        print("Вероятно простое" if fermat_primality_test(n) else "Составное")

    elif choice == "3":
        a, b = input_pair()
        g, x, y = extended_gcd(a, b)
        print(f"НОД = {g}, x = {x}, y = {y}")
        print(f"Проверка: {a}*{x} + {b}*{y} = {a*x + b*y}")

    elif choice == "4":
        a = int(input("a = "))
        y = int(input("y = "))
        p = int(input("p = "))
        x = baby_step_giant_step(a, y, p)
        print(f"x = {x}" if x is not None else "Решение не найдено")

    elif choice == "5":
        p, g, x_a, x_b = generate_diffie_hellman_instance()
        res = diffie_hellman(p, g, x_a, x_b)
        print(f"p={p}, g={g}, X_A={x_a}, X_B={x_b}")
        print(f"Y_A={res['y_a']}, Y_B={res['y_b']}, K={res['shared_key']}")

    elif choice == "6":
        print("1. Полный цикл\n2. Зашифровать C\n3. Расшифровать D")
        mode = input("Выбор (1-3): ").strip()
        if mode == "1":
            while True:
                p = random.randint(2, 251)
                if fermat_primality_test(p):
                    break
            c_a, d_a = shamir_generate_keys(p)
            c_b, d_b = shamir_generate_keys(p)
            print(f"p={p}, C_A={c_a}, D_A={d_a}, C_B={c_b}, D_B={d_b}")
            shamir_full_cycle(input("Исходный файл: ").strip(),
                              input("Выходной файл: ").strip(),
                              p, c_a, d_a, c_b, d_b)
            print("Готово.")
        elif mode == "2":
            p = int(input("p = "))
            c = int(input("C = "))
            shamir_encrypt_file(input("Исходный: ").strip(),
                                input("Выходной: ").strip(),
                                p, c, c, mode="a")
        elif mode == "3":
            p = int(input("p = "))
            d = int(input("D = "))
            shamir_decrypt_file(input("Зашифрованный: ").strip(),
                                input("Выходной: ").strip(), p, d)

    elif choice == "7":
        p, g, c, d = elgamal_generate_instance()
        print(f"p={p}, g={g}, C={c}, D={d}")
        elgamal_encrypt_file(input("Исходный: ").strip(),
                             input("Зашифрованный: ").strip(), p, g, d)
        print("Зашифровано. Для расшифрования нужен C.")

    elif choice == "8":
        print("1. Подписать\n2. Проверить")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            e, n, d = rsa_generate_keys()
            print(f"e={e}\nn={n}\nd={d}")
            rsa_sign_file(input("Файл: ").strip(),
                          input("Подпись: ").strip(), n, d)
            print("Подписано.")
        elif mode == "2":
            n = int(input("n = "))
            e = int(input("e = "))
            ok = rsa_verify_file(input("Файл: ").strip(),
                                 input("Подпись: ").strip(), n, e)
            print("Верна" if ok else "Неверна")

    elif choice == "9":
        print("1. Подписать\n2. Проверить")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            p, g, x, y = elgamal_sign_generate_params()
            print(f"p={p}, g={g}, x={x}, y={y}")
            elgamal_sign_file(input("Файл: ").strip(),
                              input("Подпись: ").strip(), p, g, x)
            print("Подписано.")
        elif mode == "2":
            p = int(input("p = "))
            g = int(input("g = "))
            y = int(input("y = "))
            ok = elgamal_verify_file(input("Файл: ").strip(),
                                     input("Подпись: ").strip(), p, g, y)
            print("Верна" if ok else "Неверна")

    elif choice == "10":
        print("1. Подписать\n2. Проверить")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            p, q, a, x, y = gost_generate_params()
            print(f"p={p}, q={q}, a={a}, x={x}, y={y}")
            gost_sign_file(input("Файл: ").strip(),
                           input("Подпись: ").strip(), p, q, a, x)
            print("Подписано.")
        elif mode == "2":
            p = int(input("p = "))
            q = int(input("q = "))
            a = int(input("a = "))
            y = int(input("y = "))
            ok = gost_verify_file(input("Файл: ").strip(),
                                  input("Подпись: ").strip(), p, q, a, y)
            print("Верна" if ok else "Неверна")

    elif choice == "11":
        print("1. Ввести p, q, D вручную\n2. Сгенерировать")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            p = int(input("p = "))
            q = int(input("q = "))
            d = int(input("D = "))
            n = p * q
            phi = (p - 1) * (q - 1)
            _, e, _ = extended_gcd(d, phi)
            e %= phi
            if e < 0:
                e += phi
            print(f"n={n}, e={e}, d={d}")
        elif mode == "2":
            p, q, e, n, d = rsa_generate_keys_enc()
            print(f"p={p}\nq={q}\nn={n}\ne={e}\nd={d}")
        else:
            return

        print("1. Зашифровать\n2. Расшифровать\n3. Ничего")
        action = input("Действие (1-3): ").strip()
        if action == "1":
            out = input("Зашифрованный файл: ").strip()
            rsa_encrypt_file_enc(input("Исходный файл: ").strip(), out, e, n)
            print("Зашифровано.")
            if input("Расшифровать? (y/n): ").strip().lower() == "y":
                rsa_decrypt_file_enc(out, input("Куда: ").strip(), d, n)
                print("Расшифровано.")
        elif action == "2":
            rsa_decrypt_file_enc(input("Зашифрованный: ").strip(),
                                 input("Куда: ").strip(), d, n)
            print("Расшифровано.")

    elif choice == "12":
        print("1. Через DH и зашифровать\n2. Зашифровать\n3. Расшифровать")
        mode = input("Выбор (1-3): ").strip()
        if mode == "1":
            inp = input("Исходный: ").strip()
            out = input("Зашифрованный: ").strip()
            key, res = vernam_generate_key_via_dh(inp)
            print(f"p={res['p']}, g={res['g']}, K={res['shared_key']}")
            vernam_encrypt_file(inp, out, key)
            print("Зашифровано.")
            if input("Расшифровать? (y/n): ").strip().lower() == "y":
                size = os.path.getsize(out)
                key2 = vernam_generate_key_from_shared(res['shared_key'], size)
                vernam_decrypt_file(out, input("Куда: ").strip(), key2)
                print("Расшифровано.")
        elif mode == "2":
            inp = input("Исходный: ").strip()
            shared = int(input("Общий секрет: "))
            key = vernam_generate_key_from_shared(shared, os.path.getsize(inp))
            vernam_encrypt_file(inp, input("Зашифрованный: ").strip(), key)
            print("Зашифровано.")
        elif mode == "3":
            inp = input("Зашифрованный: ").strip()
            shared = int(input("Общий секрет: "))
            key = vernam_generate_key_from_shared(shared, os.path.getsize(inp))
            vernam_decrypt_file(inp, input("Куда: ").strip(), key)
            print("Расшифровано.")

    elif choice == "13":
        print("1. Сгенерировать и подписать\n2. Проверить")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            p, q, g = dsa_generate_params()
            x, y = dsa_generate_keys(p, q, g)
            print(f"p = {p}")
            print(f"q = {q}")
            print(f"g = {g}")
            print(f"x = {x}")
            print(f"y = {y}")
            dsa_sign_file(input("Файл: ").strip(),
                          input("Подпись: ").strip(), p, q, g, x)
            print("Подписано.")
        elif mode == "2":
            p = int(input("p = "))
            q = int(input("q = "))
            g = int(input("g = "))
            y = int(input("y = "))
            ok = dsa_verify_file(input("Файл: ").strip(),
                                 input("Подпись: ").strip(), p, q, g, y)
            print("Верна" if ok else "Неверна")

    else:
        print("Неверный выбор")


if __name__ == "__main__":
    main()