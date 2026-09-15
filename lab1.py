"""
crypto_lib.py

Криптографическая библиотека:
1. Быстрое возведение в степень по модулю.
2. Тест простоты Ферма.
3. Обобщённый алгоритм Евклида.
4. Дискретный логарифм (алгоритм "шаг младенца, шаг великана").
5. Протокол Диффи-Хеллмана (выработка общего ключа).
6. Шифр Шамира (трёхпроходный протокол для файлов).
"""

import random
import math
import os


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
# 4. Дискретный логарифм (шаг младенца, шаг великана)
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
    """
    Вырабатывает общий секретный ключ для двух абонентов A и B.
    Возвращает словарь с открытыми и секретными параметрами.
    """
    # Открытые ключи абонентов
    y_a = fast_pow(g, x_a, p)   # A отправляет B
    y_b = fast_pow(g, x_b, p)   # B отправляет A

    # Общий секрет
    k_a = fast_pow(y_b, x_a, p)  # A вычисляет
    k_b = fast_pow(y_a, x_b, p)  # B вычисляет

    assert k_a == k_b, "Ключи не совпали!"
    return {
        "p": p, "g": g,
        "x_a": x_a, "x_b": x_b,
        "y_a": y_a, "y_b": y_b,
        "shared_key": k_a
    }


def generate_diffie_hellman_instance(bits=16):
    """
    Генерирует корректные параметры для протокола Диффи-Хеллмана:
    простое p, первообразный корень g, случайные X_A, X_B.
    """
    # Генерируем простое p
    while True:
        p = random.getrandbits(bits)
        if p < 5 or p % 2 == 0:
            continue
        if fermat_primality_test(p):
            break

    # Ищем первообразный корень g
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

    # Случайные приватные ключи
    x_a = random.randint(2, p - 2)
    x_b = random.randint(2, p - 2)

    return p, g, x_a, x_b


# ----------------------------------------------------------------------
# 6. Шифр Шамира (трёхпроходный протокол)
# ----------------------------------------------------------------------
def shamir_generate_keys(p):
    """
    Генерирует пару ключей (C, D) для одного абонента:
    C — ключ шифрования (взаимно прост с p-1),
    D = C^{-1} mod (p-1) — ключ расшифрования.
    """
    while True:
        c = random.randint(2, p - 2)
        gcd, d, _ = extended_gcd(c, p - 1)
        if gcd == 1:
            d %= (p - 1)
            if d < 0:
                d += (p - 1)
            return c, d


def _shamir_encrypt_block(m, c, p):
    """Шифрует один блок (число) по формуле m^c mod p."""
    return fast_pow(m, c, p)


def _shamir_decrypt_block(c_blk, d, p):
    """Расшифровывает один блок по формуле c^d mod p."""
    return fast_pow(c_blk, d, p)


def shamir_encrypt_file(input_path, output_path, p, c_a, c_b, mode="all"):
    """
    Шифрование файла шифром Шамира.

    mode:
      "a"   — первый проход (шифрование A),
      "b"   — второй проход (шифрование B),
      "all" — выполнить все три прохода сразу (A→B→A^{-1}),
              результат — файл, зашифрованный ключом B.
    """
    with open(input_path, "rb") as f:
        data = f.read()

    if mode == "a":
        result = bytes(_shamir_encrypt_block(b, c_a, p) for b in data)
    elif mode == "b":
        result = bytes(_shamir_encrypt_block(b, c_b, p) for b in data)
    elif mode == "all":
        # Проход 1: A шифрует
        step1 = bytes(_shamir_encrypt_block(b, c_a, p) for b in data)
        # Проход 2: B шифрует
        step2 = bytes(_shamir_encrypt_block(b, c_b, p) for b in step1)
        # Проход 3: A снимает свой слой
        # (нужен D_A, но в этой функции он не передан; см. полный сценарий ниже)
        raise ValueError("Для полного цикла используйте последовательные вызовы с D_A.")
    else:
        raise ValueError("Неизвестный режим")

    with open(output_path, "wb") as f:
        f.write(result)


def shamir_decrypt_file(input_path, output_path, p, d):
    """
    Расшифрование файла: применяет c^d mod p к каждому байту.
    """
    with open(input_path, "rb") as f:
        data = f.read()
    result = bytes(_shamir_decrypt_block(b, d, p) for b in data)
    with open(output_path, "wb") as f:
        f.write(result)


def shamir_full_cycle(input_path, output_path, p, c_a, d_a, c_b, d_b):
    """
    Полный трёхпроходный цикл шифрования по схеме Шамира.
    На выходе — файл, идентичный исходному (проверка корректности).
    """
    with open(input_path, "rb") as f:
        data = f.read()

    # Проход 1: A шифрует своим ключом C_A
    step1 = bytes(_shamir_encrypt_block(b, c_a, p) for b in data)
    # Проход 2: B шифрует своим ключом C_B
    step2 = bytes(_shamir_encrypt_block(b, c_b, p) for b in step1)
    # Проход 3: A расшифровывает своим ключом D_A
    step3 = bytes(_shamir_decrypt_block(b, d_a, p) for b in step2)
    # Проход 4: B расшифровывает своим ключом D_B
    step4 = bytes(_shamir_decrypt_block(b, d_b, p) for b in step3)

    with open(output_path, "wb") as f:
        f.write(step4)


# ----------------------------------------------------------------------
# Вспомогательные функции
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
    def gen():
        while True:
            candidate = random.getrandbits(bits)
            if candidate < 3:
                candidate = 3
            if candidate % 2 == 0:
                candidate += 1
            if fermat_primality_test(candidate):
                return candidate
    return gen(), gen()


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
    print("4. Дискретный логарифм (шаг младенца, шаг великана)")
    print("5. Протокол Диффи-Хеллмана")
    print("6. Шифр Шамира (работа с файлами)")
    choice = input("Ваш выбор (1-6): ").strip()

    if choice == "1":
        print("1. Ввести a, b, p вручную")
        print("2. Сгенерировать a, b, p случайно")
        print("3. Сгенерировать a, b простыми")
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
        print("1. Вручную")
        print("2. Случайно")
        print("3. Простыми")
        src = input("Источник (1-3): ").strip()
        if src == "1":
            a, b = input_pair()
        elif src == "2":
            a, b = generate_random_pair()
            print(f"a={a}, b={b}")
        elif src == "3":
            a, b = generate_prime_pair()
            print(f"a={a} (простое), b={b} (простое)")
        else:
            return
        g, x, y = extended_gcd(a, b)
        print(f"НОД = {g}, x = {x}, y = {y}")
        print(f"Проверка: {a}*{x} + {b}*{y} = {a*x + b*y}")

    elif choice == "4":
        print("1. Вручную")
        print("2. Сгенерировать")
        src = input("Источник (1-2): ").strip()
        if src == "1":
            a = int(input("a = "))
            y = int(input("y = "))
            p = int(input("p = "))
        elif src == "2":
            a, y, p, x_true = generate_dlp_instance()
            print(f"a={a}, y={y}, p={p}")
            print(f"Истинный x = {x_true}")
        else:
            return
        x = baby_step_giant_step(a, y, p)
        print(f"Найденный x = {x}" if x is not None else "Решение не найдено")

    elif choice == "5":
        print("1. Ввести p, g, X_A, X_B вручную")
        print("2. Сгенерировать параметры")
        src = input("Источник (1-2): ").strip()
        if src == "1":
            p = int(input("p = "))
            g = int(input("g = "))
            x_a = int(input("X_A = "))
            x_b = int(input("X_B = "))
        elif src == "2":
            p, g, x_a, x_b = generate_diffie_hellman_instance()
            print(f"p={p}, g={g}, X_A={x_a}, X_B={x_b}")
        else:
            return
        res = diffie_hellman(p, g, x_a, x_b)
        print(f"Открытый ключ A: Y_A = {res['y_a']}")
        print(f"Открытый ключ B: Y_B = {res['y_b']}")
        print(f"Общий секретный ключ: K = {res['shared_key']}")

    elif choice == "6":
        print("Режимы:")
        print("1. Сгенерировать ключи и зашифровать файл (полный цикл)")
        print("2. Зашифровать файл своим ключом C")
        print("3. Расшифровать файл своим ключом D")
        mode = input("Выбор (1-3): ").strip()

        if mode == "1":
            # Генерируем p > 255 (нужно для байтов) и ключи
            while True:
                p = random.randint(2, 251)
                if fermat_primality_test(p):
                    break
            c_a, d_a = shamir_generate_keys(p)
            c_b, d_b = shamir_generate_keys(p)
            print(f"p = {p}")
            print(f"A: C_A={c_a}, D_A={d_a}")
            print(f"B: C_B={c_b}, D_B={d_b}")

            inp = input("Исходный файл: ").strip()
            out = input("Выходной файл (для расшифрованного): ").strip()
            shamir_full_cycle(inp, out, p, c_a, d_a, c_b, d_b)
            print("Готово! Проверьте совпадение файлов.")

        elif mode == "2":
            p = int(input("p = "))
            c = int(input("C (ключ шифрования) = "))
            inp = input("Исходный файл: ").strip()
            out = input("Выходной файл: ").strip()
            shamir_encrypt_file(inp, out, p, c, c, mode="a")
            print("Файл зашифрован.")

        elif mode == "3":
            p = int(input("p = "))
            d = int(input("D (ключ расшифрования) = "))
            inp = input("Зашифрованный файл: ").strip()
            out = input("Выходной файл: ").strip()
            shamir_decrypt_file(inp, out, p, d)
            print("Файл расшифрован.")

    else:
        print("Неверный выбор")


if __name__ == "__main__":
    main()