"""
crypto_lib.py

Криптографическая библиотека:
1. Быстрое возведение в степень по модулю.
2. Тест простоты Ферма.
3. Обобщённый алгоритм Евклида.
4. Дискретный логарифм (шаг младенца, шаг великана).
5. Протокол Диффи-Хеллмана.
6. Шифр Шамира.
7. Шифр Эль-Гамаля.
8. Электронная подпись RSA.
9. Электронная подпись Эль-Гамаля.
10. Электронная подпись ГОСТ Р 34.10-94.
"""

import random
import math
import os
import hashlib


# ----------------------------------------------------------------------
# 1. Быстрое возведение в степень по модулю
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# 2. Тест простоты Ферма
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# 3. Обобщённый алгоритм Евклида
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# 4. Дискретный логарифм
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# 5. Протокол Диффи-Хеллмана
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# 6. Шифр Шамира
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# 7. Шифр Эль-Гамаля
# ----------------------------------------------------------------------
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
        raise ValueError("Некорректный формат зашифрованного файла")
    output = bytearray()
    for i in range(0, len(data), 8):
        a = int.from_bytes(data[i:i+4], "big")
        b = int.from_bytes(data[i+4:i+8], "big")
        a_c = fast_pow(a, c, p)
        gcd, inv, _ = extended_gcd(a_c, p)
        if gcd != 1:
            raise ValueError("Не удалось вычислить обратный элемент")
        inv %= p
        m = (b * inv) % p
        if m > 255:
            raise ValueError(f"Байт вне диапазона: {m}")
        output.append(m)
    with open(output_path, "wb") as f:
        f.write(output)


# ----------------------------------------------------------------------
# Вспомогательные функции для подписи
# ----------------------------------------------------------------------
def _random_prime(bits=16):
    """Генерирует случайное простое число заданной битности."""
    while True:
        candidate = random.getrandbits(bits)
        if candidate < 3:
            continue
        if candidate % 2 == 0:
            candidate += 1
        if fermat_primality_test(candidate):
            return candidate


def _hash_file(path):
    """Возвращает SHA-256 хеш файла (32 байта)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.digest()


# ----------------------------------------------------------------------
# 8. Электронная подпись RSA
# ----------------------------------------------------------------------
def rsa_generate_keys(bits=16):
    """
    Генерирует ключи RSA: (e, n, d).
    e — открытая экспонента, d — секретная, n = p*q.
    """
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
    """
    Подписывает файл: читает SHA-256 хеш, каждый байт хеша возводит
    в степень d по модулю n. Результат сохраняет в отдельный файл.
    """
    digest = _hash_file(input_path)
    sig = bytearray()
    for b in digest:
        s = fast_pow(b, d, n)
        sig += s.to_bytes(4, "big")
    with open(sig_path, "wb") as f:
        f.write(sig)


def rsa_verify_file(input_path, sig_path, n, e):
    """
    Проверяет подпись RSA. Возвращает True, если подпись верна.
    """
    digest = _hash_file(input_path)
    with open(sig_path, "rb") as f:
        sig = f.read()
    if len(sig) != len(digest) * 4:
        return False
    for i, b in enumerate(digest):
        s = int.from_bytes(sig[i*4:(i+1)*4], "big")
        m = fast_pow(s, e, n)
        if m != b:
            return False
    return True


# ----------------------------------------------------------------------
# 9. Электронная подпись Эль-Гамаля
# ----------------------------------------------------------------------
def elgamal_sign_generate_keys(p, g):
    """
    Генерирует ключи для подписи Эль-Гамаля: (x, y).
    x — секретный, y = g^x mod p — открытый.
    """
    x = random.randint(2, p - 2)
    y = fast_pow(g, x, p)
    return x, y


def elgamal_sign_generate_params(bits=16):
    """Генерирует простое p и первообразный корень g."""
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
    """
    Подписывает файл: для каждого байта хеша m вычисляет пару (r, s):
      r = g^k mod p
      s = (m - x*r) * k^{-1} mod (p-1)
    где k — случайное, взаимно простое с (p-1).
    """
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
    """
    Проверяет подпись Эль-Гамаля:
      y^r * r^s mod p == g^m mod p
    """
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
        rhs = fast_pow(g, m, p)
        if lhs != rhs:
            return False
    return True


# ----------------------------------------------------------------------
# 10. Электронная подпись ГОСТ Р 34.10-94
# ----------------------------------------------------------------------
def gost_generate_params(bits_q=16):
    """
    Генерирует параметры ГОСТ Р 34.10-94:
      p — простое, q — простой делитель (p-1),
      a — элемент порядка q по модулю p,
      x — секретный ключ, y = a^x mod p — открытый.
    """
    # 1. Простое q
    q = _random_prime(bits_q)

    # 2. p = k*q + 1 простое
    k = 2
    while True:
        p = k * q + 1
        if fermat_primality_test(p):
            break
        k += 1

    # 3. a — элемент порядка q
    while True:
        g = random.randint(2, p - 2)
        a = fast_pow(g, (p - 1) // q, p)
        if a != 1:
            break

    # 4. Ключи
    x = random.randint(1, q - 1)
    y = fast_pow(a, x, p)
    return p, q, a, x, y


def gost_sign_file(input_path, sig_path, p, q, a, x):
    """
    Подписывает файл ГОСТ Р 34.10-94. Для каждого байта хеша m:
      r = (a^k mod p) mod q
      s = (x*r + k*m) mod q
    Если r = 0 или s = 0, генерируем новый k.
    """
    digest = _hash_file(input_path)
    sig = bytearray()
    for m in digest:
        m_val = m if m != 0 else 1   # h != 0 mod q
        while True:
            k = random.randint(1, q - 1)
            r = fast_pow(a, k, p) % q
            if r == 0:
                continue
            s = (x * r + k * m_val) % q
            if s == 0:
                continue
            break
        sig += r.to_bytes(4, "big")
        sig += s.to_bytes(4, "big")
    with open(sig_path, "wb") as f:
        f.write(sig)


def gost_verify_file(input_path, sig_path, p, q, a, y):
    """
    Проверяет подпись ГОСТ Р 34.10-94:
      v  = m^{-1} mod q
      z1 = s*v mod q
      z2 = (q - r)*v mod q
      u  = (a^z1 * y^z2 mod p) mod q
      подпись верна, если u == r
    """
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


# ----------------------------------------------------------------------
# Вспомогательные функции (ввод, генерация)
# ----------------------------------------------------------------------
def input_pair(prompt="Введите два целых числа через пробел: "):
    while True:
        try:
            s = input(prompt)
            a_str, b_str = s.split()
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
    y = fast_pow(a, x, p)
    return a, y, p, x


# ----------------------------------------------------------------------
# Интерактивное меню
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
    choice = input("Ваш выбор (1-10): ").strip()

    if choice == "1":
        print("1. Ввести a, b, p вручную")
        print("2. Сгенерировать случайно")
        print("3. Сгенерировать простыми")
        src = input("Источник (1-3): ").strip()
        if src == "1":
            a, b = input_pair("Введите a и b: ")
            p = int(input("Введите модуль p: "))
        elif src == "2":
            a, b = generate_random_pair()
            p = random.getrandbits(16) + 2
            print(f"a={a}, b={b}, p={p}")
        elif src == "3":
            a, b = generate_prime_pair()
            p = random.getrandbits(16) + 2
            print(f"a={a} (простое), b={b} (простое), p={p}")
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
        print(f"Найденный x = {x}" if x is not None else "Решение не найдено")

    elif choice == "5":
        p, g, x_a, x_b = generate_diffie_hellman_instance()
        print(f"p={p}, g={g}, X_A={x_a}, X_B={x_b}")
        res = diffie_hellman(p, g, x_a, x_b)
        print(f"Y_A = {res['y_a']}, Y_B = {res['y_b']}")
        print(f"Общий ключ: K = {res['shared_key']}")

    elif choice == "6":
        print("1. Полный цикл (A→B→A⁻¹→B⁻¹)")
        print("2. Зашифровать ключом C")
        print("3. Расшифровать ключом D")
        mode = input("Выбор (1-3): ").strip()
        if mode == "1":
            while True:
                p = random.randint(2, 251)
                if fermat_primality_test(p):
                    break
            c_a, d_a = shamir_generate_keys(p)
            c_b, d_b = shamir_generate_keys(p)
            print(f"p={p}, A: C_A={c_a}, D_A={d_a}, B: C_B={c_b}, D_B={d_b}")
            inp = input("Исходный файл: ").strip()
            out = input("Выходной файл: ").strip()
            shamir_full_cycle(inp, out, p, c_a, d_a, c_b, d_b)
            print("Готово.")
        elif mode == "2":
            p = int(input("p = "))
            c = int(input("C = "))
            inp = input("Исходный файл: ").strip()
            out = input("Выходной файл: ").strip()
            shamir_encrypt_file(inp, out, p, c, c, mode="a")
        elif mode == "3":
            p = int(input("p = "))
            d = int(input("D = "))
            inp = input("Зашифрованный файл: ").strip()
            out = input("Выходной файл: ").strip()
            shamir_decrypt_file(inp, out, p, d)

    elif choice == "7":
        p, g, c, d = elgamal_generate_instance()
        print(f"p={p}, g={g}, C={c}, D={d}")
        inp = input("Исходный файл: ").strip()
        out = input("Выходной (зашифрованный) файл: ").strip()
        elgamal_encrypt_file(inp, out, p, g, d)
        print("Файл зашифрован. Для расшифрования нужен C.")

    elif choice == "8":
        print("1. Сгенерировать ключи и подписать файл")
        print("2. Проверить подпись")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            e, n, d = rsa_generate_keys()
            print(f"e = {e}\nn = {n}\nd = {d}")
            inp = input("Файл для подписи: ").strip()
            sig = input("Файл подписи: ").strip()
            rsa_sign_file(inp, sig, n, d)
            print("Файл подписан.")
        elif mode == "2":
            n = int(input("n = "))
            e = int(input("e = "))
            inp = input("Файл: ").strip()
            sig = input("Файл подписи: ").strip()
            ok = rsa_verify_file(inp, sig, n, e)
            print("Подпись верна" if ok else "Подпись неверна")

    elif choice == "9":
        print("1. Сгенерировать параметры и подписать файл")
        print("2. Проверить подпись")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            p, g, x, y = elgamal_sign_generate_params()
            print(f"p = {p}\ng = {g}\nx = {x}\ny = {y}")
            inp = input("Файл для подписи: ").strip()
            sig = input("Файл подписи: ").strip()
            elgamal_sign_file(inp, sig, p, g, x)
            print("Файл подписан.")
        elif mode == "2":
            p = int(input("p = "))
            g = int(input("g = "))
            y = int(input("y = "))
            inp = input("Файл: ").strip()
            sig = input("Файл подписи: ").strip()
            ok = elgamal_verify_file(inp, sig, p, g, y)
            print("Подпись верна" if ok else "Подпись неверна")

    elif choice == "10":
        print("1. Сгенерировать параметры и подписать файл")
        print("2. Проверить подпись")
        mode = input("Выбор (1-2): ").strip()
        if mode == "1":
            p, q, a, x, y = gost_generate_params()
            print(f"p = {p}\nq = {q}\na = {a}\nx = {x}\ny = {y}")
            inp = input("Файл для подписи: ").strip()
            sig = input("Файл подписи: ").strip()
            gost_sign_file(inp, sig, p, q, a, x)
            print("Файл подписан.")
        elif mode == "2":
            p = int(input("p = "))
            q = int(input("q = "))
            a = int(input("a = "))
            y = int(input("y = "))
            inp = input("Файл: ").strip()
            sig = input("Файл подписи: ").strip()
            ok = gost_verify_file(inp, sig, p, q, a, y)
            print("Подпись верна" if ok else "Подпись неверна")

    else:
        print("Неверный выбор")


if __name__ == "__main__":
    main()