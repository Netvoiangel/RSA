import gmpy2
import random
import os


def generate_random_number(bit_length):
    random_bits = gmpy2.mpz(random.getrandbits(bit_length))
    return random_bits | 1  

def power_mod(base, exp, mod):
    result = gmpy2.mpz(1)
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def generate_random_in_range(min_val, max_val):
    range_val = max_val - min_val + 1
    while True:
        candidate = generate_random_number(gmpy2.bit_length(range_val))
        if min_val <= candidate < max_val:
            return candidate


def miller_rabin_test(n, k=25):
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True

    d = n - 1
    r = 0

    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = generate_random_in_range(2, n - 2)
        x = power_mod(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = power_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bit_length):
    while True:
        candidate = generate_random_number(bit_length)
        if miller_rabin_test(candidate):
            return candidate


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a, n):
    gcd, x, _ = extended_gcd(a, n)
    if gcd != 1:
        raise ValueError("Мультипликативного обратного элемента не существует.")
    return x % n


def generate_keys(public_key_file, private_key_file):
    bit_length = 1024

    p = generate_prime(bit_length)
    q = generate_prime(bit_length)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = gmpy2.mpz(65537) 
    d = mod_inverse(e, phi)

    os.mkdir("keys")

    with open(f"keys/{public_key_file}", "w") as pub_file:
        pub_file.write(f"{e}\n{n}\n")

    with open(f"keys/{private_key_file}", "w") as priv_file:
        priv_file.write(f"{d}\n{n}\n")

    print("Ключи успешно сгенерированы и сохранены.")


def string_to_integer(message):
    num = gmpy2.mpz(0)
    for char in message:
        num = (num << 8) + ord(char)
    return num


def encrypt(input_file, output_file, public_key_file):
    with open(f"keys/{public_key_file}", "r") as pub_file:
        e = gmpy2.mpz(pub_file.readline().strip())
        n = gmpy2.mpz(pub_file.readline().strip())

    with open(input_file, "r", encoding="utf-8") as in_file:
        message = in_file.read()

    m = string_to_integer(message)
    c = power_mod(m, e, n)

    with open(output_file, "w") as out_file:
        out_file.write(f"{c}\n")

    print("Сообщение успешно зашифровано.")


def integer_to_string(num):
    result = []
    while num > 0:
        result.append(chr(num & 0xFF))
        num >>= 8
    return ''.join(result[::-1])


def decrypt(input_file, output_file, private_key_file):
    with open(f"keys/{private_key_file}", "r") as priv_file:
        d = gmpy2.mpz(priv_file.readline().strip())
        n = gmpy2.mpz(priv_file.readline().strip())

    with open(input_file, "r") as in_file:
        c = gmpy2.mpz(in_file.read().strip())

    m = power_mod(c, d, n)
    message = integer_to_string(m)

    with open(output_file, "w", encoding="utf-8") as out_file:
        out_file.write(message)

    print("Сообщение успешно расшифровано.")


def main():
    while True:
        print("Выберите операцию:\n1. Генерация ключей\n2. Шифрование\n3. Расшифрование\n0. Выход")
        choice = int(input())

        if choice == 0:
            print("Выход из программы.")
            break

        elif choice == 1:
            public_key_file = input("Введите имя файла для сохранения открытого ключа: ")
            private_key_file = input("Введите имя файла для сохранения закрытого ключа: ")
            generate_keys(public_key_file, private_key_file)

        elif choice == 2:
            input_file = input("Введите имя файла для шифрования: ")
            output_file = input("Введите имя выходного файла для сохранения зашифрованного текста: ")
            public_key_file = input("Введите имя файла с открытым ключом: ")
            encrypt(input_file, output_file, public_key_file)

        elif choice == 3:
            input_file = input("Введите имя зашифрованного файла для расшифрования: ")
            output_file = input("Введите имя выходного файла для сохранения расшифрованного текста: ")
            private_key_file = input("Введите имя файла с закрытым ключом: ")
            decrypt(input_file, output_file, private_key_file)

        else:
            print("Неверный выбор. Попробуйте снова.")


if __name__ == "__main__":
    main()
