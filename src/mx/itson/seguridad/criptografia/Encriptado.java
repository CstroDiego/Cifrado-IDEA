package mx.itson.seguridad.criptografia;

public abstract class Encriptado {


  /**
   * El tamaño del bloque.
   */
  protected int blockSize;

  /**
   * Qué tan grande es una llave. Los cifrados sin clave usan 0.
   * Los cifrados de clave de longitud variable también usan 0.
   */
  protected int keySize;

  /**
   * Metodo de encriptado
   *
   */
  public abstract String encrypt(String text);

  /**
   * Metodo de desencriptado
   *
   */
  public abstract String decrypt(String text);

  /**
   * Se usa para convertir un String en una clave de la longitud adecuada.
   *
   */
  protected byte[] makeKey(String keyStr) {
    byte[] key;
    if (keySize == 0) {
      key = new byte[keyStr.length()];
    } else {
      key = new byte[keySize];
    }
    int i, j;

    for (j = 0; j < key.length; ++j) {
      key[j] = 0;
    }

    for (i = 0, j = 0; i < keyStr.length(); ++i, j = (j + 1) % key.length) {
      key[j] ^= (byte) keyStr.charAt(i);
    }

    return key;
  }

  /**
   * Incrustamos la llave
   *
   */
  protected abstract void setKey(byte[] key);

  /**
   * Convierte la llave.
   *
   */
  protected void setKey(String keyStr) {
    setKey(makeKey(keyStr));
  }

}