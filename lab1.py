import random
import math
import os


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

def diffie_hellman(p, g, x_a, x_b):

    y_a = fast_pow(g, x_a, p)  
    y_b = fast_pow(g, x_b, p)  

    k_a = fast_pow(y_b, x_a, p)  
    k_b = fast_pow(y_a, x_b, p)  

    assert k_a == k_b, "Ключи не совпали!"
    return {
        "p": p, "g": g,
        "x_a": x_a, "x_b": x_b,
        "y_a": y_a, "y_b": y_b,
        "shared_key": k_a
    }


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
    elif mode == "all":
        step1 = bytes(_shamir_encrypt_block(b, c_a, p) for b in data)
        step2 = bytes(_shamir_encrypt_block(b, c_b, p) for b in step1)
        raise ValueError("Для полного цикла используйте последовательные вызовы с D_A.")
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

# 7. 

def elgamal_generate_keys(p, g):
    """
    Генерирует пару ключей (C, D) для шифра Эль-Гамаля:
    C — секретный ключ (случайное число),
    D = g^C mod p — открытый ключ.
    """
    c = random.randint(2, p - 2)
    d = fast_pow(g, c, p)
    return c, d


def elgamal_generate_instance(bits=16):
    """
    Генерирует все параметры для шифра Эль-Гамаля:
    простое p, первообразный корень g, секретный C и открытый D.
    """
    # Генерируем простое p
    while True:
        p = random.getrandbits(bits)
        if p < 257 or p % 2 == 0:  # p должно быть > 255, чтобы шифровать байты
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

    # Генерируем ключи
    c, d = elgamal_generate_keys(p, g)

    return p, g, c, d


def elgamal_encrypt_file(input_path, output_path, p, g, d):
    """
    Шифрует файл шифром Эль-Гамаля.
    Каждый байт шифруется отдельно как число m < p.
    Для каждого байта генерируется свой сеансовый ключ k.
    Формат выходного файла: последовательность пар (a, b), каждая — 4 байта.
    """
    with open(input_path, "rb") as f:
        data = f.read()

    output = bytearray()
    for m in data:
        k = random.randint(2, p - 2)
        a = fast_pow(g, k, p)
        b = (m * fast_pow(d, k, p)) % p

        # Записываем a и b как 4-байтовые числа (big-endian)
        output += a.to_bytes(4, "big")
        output += b.to_bytes(4, "big")

    with open(output_path, "wb") as f:
        f.write(output)


def elgamal_decrypt_file(input_path, output_path, p, c):
    """
    Расшифровывает файл шифром Эль-Гамаля.
    Каждые 8 байт — это пара (a, b), где a и b — 4-байтовые числа.
    Восстанавливает m = b * (a^C)^{-1} mod p.
    """
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
            raise ValueError(f"Расшифрованный байт вне диапазона: {m}")
        output.append(m)

    with open(output_path, "wb") as f:
        f.write(output)

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
    print("7. Шифр Эль-Гамаля (работа с файлами)")
    choice = input("Ваш выбор (1-7): ").strip()

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

    elif choice == "7":
        print("Режимы:")
        print("1. Сгенерировать/ввести ключи и зашифровать файл")
        print("2. Расшифровать файл")
        mode = input("Выбор (1-2): ").strip()

        if mode == "1":
            print("1. Ввести p, g, C вручную")
            print("2. Сгенерировать p, g, C, D автоматически")
            src = input("Источник (1-2): ").strip()
            if src == "1":
                p = int(input("p = "))
                g = int(input("g = "))
                c = int(input("C (секретный ключ) = "))
                d = fast_pow(g, c, p)
                print(f"D (открытый ключ) = {d}")
            elif src == "2":
                p, g, c, d = elgamal_generate_instance()
                print(f"p = {p}")
                print(f"g = {g}")
                print(f"C (секретный) = {c}")
                print(f"D (открытый)  = {d}")
            else:
                return

            inp = input("Исходный файл: ").strip()
            out = input("Выходной (зашифрованный) файл: ").strip()
            elgamal_encrypt_file(inp, out, p, g, d)
            print("Файл зашифрован.")

        elif mode == "2":
            p = int(input("p = "))
            c = int(input("C (секретный ключ) = "))
            inp = input("Зашифрованный файл: ").strip()
            out = input("Выходной (расшифрованный) файл: ").strip()
            elgamal_decrypt_file(inp, out, p, c)
            print("Файл расшифрован.")

    else:
        print("Неверный выбор")


if __name__ == "__main__":
    main()