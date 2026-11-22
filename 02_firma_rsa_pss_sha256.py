from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generar_par_claves_rsa(key_size: int = 2048):
    """Genera un par de claves RSA (privada y pública)."""
    clave_privada = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica


def firmar_mensaje(mensaje: bytes, clave_privada) -> bytes: # type: ignore
    """Firma el mensaje usando RSA-PSS con hash SHA-256."""
    firma = clave_privada.sign( # type: ignore
        mensaje,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return firma # type: ignore


def verificar_firma(mensaje: bytes, firma: bytes, clave_publica) -> bool: # type: ignore
    """Verifica la firma usando la clave pública, RSA-PSS y SHA-256."""
    try:
        clave_publica.verify( # type: ignore
            firma,
            mensaje,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def alterar_un_caracter(mensaje: bytes) -> bytes:
    """Modifica un solo byte/carácter del mensaje para probar la detección de alteración."""
    if not mensaje:
        return b"A"
    datos = bytearray(mensaje)
    # Cambiamos el último carácter por uno distinto
    ultimo = datos[-1]
    datos[-1] = ord("X") if ultimo != ord("X") else ord("Y")
    return bytes(datos)


if __name__ == "__main__":
    mensaje_original = (
        "Reporte de operacion SECURELINK: todos los nodos verificados correctamente."
    ).encode("utf-8")

    privada, publica = generar_par_claves_rsa(2048)
    firma_valida = firmar_mensaje(mensaje_original, privada)

    print("1) Mensaje original:", mensaje_original.decode("utf-8"))
    print("   Firma (hex):", firma_valida.hex()[:80] + "...")
    print("   Verificación con mensaje original:", verificar_firma(mensaje_original, firma_valida, publica))

    mensaje_alterado = alterar_un_caracter(mensaje_original)
    print("\n2) Mensaje alterado (1 carácter):", mensaje_alterado.decode("utf-8"))
    print("   Verificación tras alterar 1 carácter:", verificar_firma(mensaje_alterado, firma_valida, publica))

    print(
        "\n[NOTA CONCEPTUAL] La firma digital con RSA-PSS + SHA-256 comprueba INTEGRIDAD "
        "(si el mensaje cambió, la verificación falla) y AUTENTICIDAD/NO REPUDIO (solo quien "
        "posee la clave privada pudo generar la firma), pero NO cifra ni oculta el contenido del mensaje."
    )