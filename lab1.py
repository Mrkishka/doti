import random
import math


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

def input_pair(prompt="Введите два целых числа через пробел: "):

    while True:
        try:
            s = input(prompt)
            a_str, b_str = s.split()
            a = int(a_str)
            b = int(b_str)
            return a, b
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

    def generate_prime():
        while True:
            candidate = random.getrandbits(bits)
            if candidate < 3:
                candidate = 3
            if candidate % 2 == 0:
                candidate += 1
            if fermat_primality_test(candidate):
                return candidate

    return generate_prime(), generate_prime()


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

def main():
    print("Криптографическая библиотека")
    print("Выберите действие:")
    print("1. Быстрое возведение в степень по модулю")
    print("2. Тест простоты Ферма")
    print("3. Обобщённый алгоритм Евклида")
    print("4. Дискретный логарифм (шаг младенца, шаг великана)")
    choice = input("Ваш выбор (1-4): ").strip()

    if choice == "1":
        print("Выберите источник данных:")
        print("1. Ввести a, b, p с клавиатуры")
        print("2. Сгенерировать a, b, p случайно")
        print("3. Сгенерировать a, b простыми, p случайно")
        src = input("Источник (1-3): ").strip()
        if src == "1":
            a, b = input_pair("Введите основание a и степень b: ")
            p = int(input("Введите модуль p: "))
        elif src == "2":
            a, b = generate_random_pair()
            p = random.getrandbits(16) + 2
            print(f"Сгенерированы: a={a}, b={b}, p={p}")
        elif src == "3":
            a, b = generate_prime_pair()
            p = random.getrandbits(16) + 2
            print(f"Сгенерированы: a={a} (простое), b={b} (простое), p={p}")
        else:
            print("Неверный выбор")
            return
        result = fast_pow(a, b, p)
        print(f"Результат: {a}^{b} mod {p} = {result}")

    elif choice == "2":
        n = int(input("Введите число для проверки на простоту: "))
        if fermat_primality_test(n):
            print(f"Число {n} вероятно простое")
        else:
            print(f"Число {n} составное")

    elif choice == "3":
        print("Выберите источник данных:")
        print("1. Ввести a, b с клавиатуры")
        print("2. Сгенерировать a, b случайно")
        print("3. Сгенерировать a, b простыми")
        src = input("Источник (1-3): ").strip()
        if src == "1":
            a, b = input_pair()
        elif src == "2":
            a, b = generate_random_pair()
            print(f"Сгенерированы: a={a}, b={b}")
        elif src == "3":
            a, b = generate_prime_pair()
            print(f"Сгенерированы: a={a} (простое), b={b} (простое)")
        else:
            print("Неверный выбор")
            return
        gcd, x, y = extended_gcd(a, b)
        print(f"НОД({a}, {b}) = {gcd}")
        print(f"Коэффициенты: x={x}, y={y}")
        print(f"Проверка: {a}*{x} + {b}*{y} = {a*x + b*y}")

    elif choice == "4":
        print("Выберите источник данных:")
        print("1. Ввести a, y, p с клавиатуры")
        print("2. Сгенерировать задачу (p простое, y = a^x mod p)")
        src = input("Источник (1-2): ").strip()
        if src == "1":
            a = int(input("Введите основание a: "))
            y = int(input("Введите значение y: "))
            p = int(input("Введите модуль p: "))
            true_x = None
        elif src == "2":
            a, y, p, true_x = generate_dlp_instance()
            print(f"Сгенерированы: a={a}, y={y}, p={p}")
            print(f"Истинное значение x (для проверки): {true_x}")
        else:
            print("Неверный выбор")
            return

        x = baby_step_giant_step(a, y, p)
        if x is not None:
            print(f"Дискретный логарифм x = {x}")
            print(f"Проверка: {a}^{x} mod {p} = {fast_pow(a, x, p)}")
        else:
            print("Решение не найдено (проверьте входные данные)")

    else:
        print("Неверный выбор")


if __name__ == "__main__":
    main()