def ksa(clave: bytes) -> list[int]:
    """Key-Scheduling Algorithm (KSA) de RC4 (uso exclusivamente didáctico)."""
    if not clave:
        raise ValueError("La clave RC4 no puede estar vacía.")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + clave[i % len(clave)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def prga(s: list[int], longitud: int):
    """Pseudo-Random Generation Algorithm (PRGA) de RC4: genera el flujo de bytes."""
    i = 0
    j = 0
    for _ in range(longitud):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        yield k


def rc4_procesar(datos: bytes, clave: bytes) -> bytes:
    """Cifra o descifra aplicando XOR byte a byte contra el keystream de RC4."""
    estado = ksa(clave)
    flujo = prga(estado, len(datos))
    return bytes(b ^ k for b, k in zip(datos, flujo))


if __name__ == "__main__":
    # Mensaje ficticio de prueba (no es credencial ni token real)
    mensaje_ficticio = "Mensaje ficticio de prueba para laboratorio SECURELINK #01."
    clave_definida = b"ClavePruebaDidacticaRC4"

    cifrado = rc4_procesar(mensaje_ficticio.encode("utf-8"), clave_definida)
    descifrado = rc4_procesar(cifrado, clave_definida).decode("utf-8")

    print("Mensaje original (ficticio):", mensaje_ficticio)
    print("Mensaje cifrado (hex):", cifrado.hex())
    print("Mensaje descifrado:", descifrado)
    print(
        "\n[AVISO] RC4 es un cifrado de flujo OBSOLETO e inseguro en sistemas reales; "
        "este script se emplea únicamente con fines didácticos."
    )