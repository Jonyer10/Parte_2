from pathlib import Path

MASK_32 = 0xFFFFFFFF


def rotl32(val: int, shift: int) -> int:
    """Rotación circular a la izquierda de 32 bits."""
    shift &= 31
    val &= MASK_32
    return ((val << shift) | (val >> (32 - shift))) & MASK_32


def rotr32(val: int, shift: int) -> int:
    """Rotación circular a la derecha de 32 bits."""
    shift &= 31
    val &= MASK_32
    return ((val >> shift) | (val << (32 - shift))) & MASK_32


def expandir_clave(clave: bytes, rondas: int = 12) -> list[int]:
    """Deriva subclaves de 32 bits de forma didáctica a partir de la clave."""
    if not clave:
        raise ValueError("La clave no puede estar vacía.")
    semilla = 0xB7E15163  # Constante didáctica estilo RC5 (derivada de e)
    paso = 0x9E3779B9     # Constante didáctica estilo RC5 (razón áurea)
    subclaves = [((semilla + i * paso) & MASK_32) for i in range(2 * (rondas + 1))]

    # Mezcla sencilla con los bytes de la clave
    idx_clave = 0
    acum = 0
    for i in range(len(subclaves)):
        byte_val = clave[idx_clave % len(clave)]
        acum = rotl32((subclaves[i] + acum + byte_val) & MASK_32, 3)
        subclaves[i] = acum
        idx_clave += 1
    return subclaves


def cifrar_bloque_64bits(bloque: bytes, subclaves: list[int], rondas: int = 12) -> bytes:
    """
    Simulación didáctica de un bloque de 8 bytes (dos palabras de 32 bits: A y B)
    inspirada en RC5/RC6 usando suma modular (mod 2^32), XOR y rotaciones.
    """
    bloque_ajustado = bloque.ljust(8, b"\x00")
    a = int.from_bytes(bloque_ajustado[:4], "little")
    b = int.from_bytes(bloque_ajustado[4:], "little")

    a = (a + subclaves[0]) & MASK_32
    b = (b + subclaves[1]) & MASK_32

    for i in range(1, rondas + 1):
        a = (rotl32(a ^ b, b) + subclaves[2 * i]) & MASK_32
        b = (rotl32(b ^ a, a) + subclaves[2 * i + 1]) & MASK_32

    return a.to_bytes(4, "little") + b.to_bytes(4, "little")


def descifrar_bloque_64bits(bloque: bytes, subclaves: list[int], rondas: int = 12) -> bytes:
    """Operación inversa didáctica para verificar la recuperación del bloque."""
    a = int.from_bytes(bloque[:4], "little")
    b = int.from_bytes(bloque[4:], "little")

    for i in range(rondas, 0, -1):
        b = rotr32((b - subclaves[2 * i + 1]) & MASK_32, a) ^ a
        a = rotr32((a - subclaves[2 * i]) & MASK_32, b) ^ b

    b = (b - subclaves[1]) & MASK_32
    a = (a - subclaves[0]) & MASK_32

    return a.to_bytes(4, "little") + b.to_bytes(4, "little")


def procesar_archivo_txt(ruta_entrada: str, ruta_salida: str, clave_texto: str, rondas: int = 12) -> None:
    entrada = Path(ruta_entrada)
    salida = Path(ruta_salida)

    datos = entrada.read_bytes()
    subclaves = expandir_clave(clave_texto.encode("utf-8"), rondas=rondas)

    # Guardamos la longitud original (4 bytes) al inicio para recortar padding al descifrar
    longitud_original = len(datos).to_bytes(4, "little")
    buffer = longitud_original + datos

    resultado = bytearray()
    for offset in range(0, len(buffer), 8):
        bloque = buffer[offset : offset + 8]
        resultado.extend(cifrar_bloque_64bits(bloque, subclaves, rondas=rondas))

    salida.write_bytes(bytes(resultado))
    print(f"[OK] Archivo generado: {salida} ({len(resultado)} bytes)")


def verificar_descifrado_didactico(ruta_cifrado: str, clave_texto: str, rondas: int = 12) -> str:
    """Solo para prueba didáctica: recupera el texto original."""
    cifrado = Path(ruta_cifrado).read_bytes()
    subclaves = expandir_clave(clave_texto.encode("utf-8"), rondas=rondas)

    recuperado = bytearray()
    for offset in range(0, len(cifrado), 8):
        bloque = cifrado[offset : offset + 8]
        recuperado.extend(descifrar_bloque_64bits(bloque, subclaves, rondas=rondas))

    longitud_original = int.from_bytes(recuperado[:4], "little")
    texto_limpio = bytes(recuperado[4 : 4 + longitud_original])
    return texto_limpio.decode("utf-8", errors="replace")


if __name__ == "__main__":
    archivo_entrada = Path("mensaje_prueba.txt")
    archivo_salida = Path("mensaje_cifrado_rc5_rc6.bin.txt")

    if not archivo_entrada.exists():
        archivo_entrada.write_text(
            "Hola equipo SECURELINK: esta es una prueba didactica de cifrado por bloques estilo RC5/RC6.",
            encoding="utf-8",
        )

    clave_demo = "ClaveDidacticaSecureLink2026"
    procesar_archivo_txt(str(archivo_entrada), str(archivo_salida), clave_demo, rondas=12)

    texto_recuperado = verificar_descifrado_didactico(str(archivo_salida), clave_demo, rondas=12)
    print("[VERIFICACION DIDACTICA] Texto recuperado:", texto_recuperado)
    print(
        "[AVISO] Implementacion exclusivamente didactica; NO usar en produccion ni con datos reales."
    )