package mx.itson.seguridad.criptografia.algoritmo;

import java.util.ArrayList;
import java.util.List;
import mx.itson.seguridad.criptografia.Encriptado;

public class IDEA extends Encriptado {

  /**
   * Constructor
   */
  public IDEA(String keyStr) {
    keySize = 16;
    blockSize = 8;
    setKey(keyStr);
  }

  /**
   * Metodo de encriptado
   * @param text
   * @return
   */
  @Override
  public String encrypt(String text) {
    StringBuffer result = new StringBuffer();

    int charactersAdded = 0;
    List<String> clearTextList = new ArrayList<String>();
    if (text != null) {
      if (text.length() == 8) {
        clearTextList.add(text);
      } else {
        int mod = text.length() % blockSize;
        if (mod != 0) {
          mod = blockSize - mod;
          for (int i = 0; i < mod; i++) {
            text = text.concat(charToAdd); //agregar espacios al final
            charactersAdded++;
          }
        }

        for (int i = 0; i < text.length() / blockSize; i++) {
          clearTextList.add(text.substring(i * blockSize, i * blockSize + blockSize));
        }
      }

      for (String clearText : clearTextList) {
        byte[] clearTextByte = clearText.getBytes();
        byte[] encryptedTextByte = new byte[clearTextByte.length];

        encrypt(clearTextByte, 0, encryptedTextByte, 0);

        result.append(new String(encryptedTextByte));
      }
    }

    return result.toString();
  }

  /**
   * Metodo de desencriptado
   * @param text
   * @return
   */
  @Override
  public String decrypt(String text) {
    StringBuffer result = new StringBuffer();

    int charactersAdded = 0;
    List<String> encryptedTextList = new ArrayList<String>();
    if (text != null) {
      if (text.length() == 8) {
        encryptedTextList.add(text);
      } else {
        int mod = text.length() % blockSize;
        if (mod != 0) {
          mod = blockSize - mod;
          for (int i = 0; i < mod; i++) {
            charactersAdded++;
            text = text.concat(charToAdd);
          }
        }

        for (int i = 0; i < text.length() / blockSize; i++) {
          encryptedTextList.add(text.substring(i * blockSize, i * blockSize + blockSize));
        }
      }

      for (String encryptedText : encryptedTextList) {
        byte[] encryptedTextByte = encryptedText.getBytes();
        byte[] decryptedTextByte = new byte[encryptedTextByte.length];

        decrypt(encryptedTextByte, 0, decryptedTextByte, 0);

        result.append(new String(decryptedTextByte));
      }
    }

    return result.toString();
  }

  /**
   * Encriptar por bloque
   */
  private void idea(int[] inShorts, int[] outShorts, int[] keys) {
    int x1, x2, x3, x4, k, t1, t2;

    x1 = inShorts[0];
    x2 = inShorts[1];
    x3 = inShorts[2];
    x4 = inShorts[3];
    k = 0;
    for (int round = 0; round < 8; ++round) {
      x1 = multiplicationModulo(x1 & 0xffff, keys[k++]);
      x2 = x2 + keys[k++];
      x3 = x3 + keys[k++];
      x4 = multiplicationModulo(x4 & 0xffff, keys[k++]);
      t2 = x1 ^ x3;
      t2 = multiplicationModulo(t2 & 0xffff, keys[k++]);
      t1 = t2 + (x2 ^ x4);
      t1 = multiplicationModulo(t1 & 0xffff, keys[k++]);
      t2 = t1 + t2;
      x1 ^= t1;
      x4 ^= t2;
      t2 ^= x2;
      x2 = x3 ^ t1;
      x3 = t2;
    }
    outShorts[0] = multiplicationModulo(x1 & 0xffff, keys[k++]) & 0xffff;
    outShorts[1] = (x3 + keys[k++]) & 0xffff;
    outShorts[2] = (x2 + keys[k++]) & 0xffff;
    outShorts[3] = multiplicationModulo(x4 & 0xffff, keys[k++]) & 0xffff;
  }

  /**
   * Establecer la clave.
   */
  protected void setKey(byte[] key) {
    int k1, k2, j;
    int t1, t2, t3;

    // Claves de cifrado. Los primeros 8 valores clave provienen de los 16
    // bytes de clave proporcionados
    for (k1 = 0; k1 < 8; ++k1) {
      encryptKeys[k1] = ((key[2 * k1] & 0xff) << 8) | (key[2 * k1 + 1] & 0xff);
    }

    // Los valores clave posteriores son los valores anteriores rotados al
    // a la izquierda en 25 bits.
    for (; k1 < 52; ++k1) {
      encryptKeys[k1] = ((encryptKeys[k1 - 8] << 9) | (encryptKeys[k1 - 7] >>> 7)) & 0xffff;
    }

    // Claves de descifrado. Estas son las claves de cifrado, invertidas y
    // en orden inverso.
    k1 = 0;
    k2 = 51;
    t1 = mulinv(encryptKeys[k1++]);
    t2 = -encryptKeys[k1++];
    t3 = -encryptKeys[k1++];
    decryptKeys[k2--] = mulinv(encryptKeys[k1++]);
    decryptKeys[k2--] = t3;
    decryptKeys[k2--] = t2;
    decryptKeys[k2--] = t1;
    for (j = 1; j < 8; ++j) {
      t1 = encryptKeys[k1++];
      decryptKeys[k2--] = encryptKeys[k1++];
      decryptKeys[k2--] = t1;
      t1 = mulinv(encryptKeys[k1++]);
      t2 = -encryptKeys[k1++];
      t3 = -encryptKeys[k1++];
      decryptKeys[k2--] = mulinv(encryptKeys[k1++]);
      decryptKeys[k2--] = t2;
      decryptKeys[k2--] = t3;
      decryptKeys[k2--] = t1;
    }
    t1 = encryptKeys[k1++];
    decryptKeys[k2--] = encryptKeys[k1++];
    decryptKeys[k2--] = t1;
    t1 = mulinv(encryptKeys[k1++]);
    t2 = -encryptKeys[k1++];
    t3 = -encryptKeys[k1++];
    decryptKeys[k2--] = mulinv(encryptKeys[k1++]);
    decryptKeys[k2--] = t3;
    decryptKeys[k2--] = t2;
    decryptKeys[k2--] = t1;
  }

  /**
   * Se agrega un espacio hasta hacer que el bloque sea de tamaño 8
   */
  private final String charToAdd = " ";

  /**
   * Array de llave
   */
  private final int[] encryptKeys = new int[52];
  private final int[] decryptKeys = new int[52];

  /**
   * Array de shorts temporales
   */
  private final int[] tempShorts = new int[4];

  /**
   * Multiplicacion del modulo
   */
  private static int multiplicationModulo(int a, int b) {
    int ab = a * b;
    if (ab != 0) {
      int lo = ab & 0xffff;
      int hi = ab >>> 16;
      return ((lo - hi) + (lo < hi ? 1 : 0)) & 0xffff;
    }
    if (a != 0) {
      return (1 - a) & 0xffff;
    }
    return (1 - b) & 0xffff;
  }

  /**
   * Multiplicamos al inverso para decifrar
   * @param x
   * @return
   */
  private static int mulinv(int x) {
    int t0, t1, q, y;
    if (x <= 1) {
      return x;
    }
    t0 = 1;
    t1 = 0x10001 / x;
    y = (0x10001 % x) & 0xffff;
    for (; ; ) {
      if (y == 1) {
        return (1 - t1) & 0xffff;
      }
      q = x / y;
      x = x % y;
      t0 = (t0 + q * t1) & 0xffff;
      if (x == 1) {
        return t0;
      }
      q = y / x;
      y = y % x;
      t1 = (t1 + q * t0) & 0xffff;
    }
  }

  /**
   * Encriptar un bloque de ocho bytes.
   */
  private void encrypt(byte[] clearText, int clearOff, byte[] cipherText, int cipherOff) {
    squashBytesToShorts(clearText, clearOff, tempShorts, 0, 4);
    idea(tempShorts, tempShorts, encryptKeys);
    spreadShortsToBytes(tempShorts, 0, cipherText, cipherOff, 4);
  }

  /**
   * Desencriptar un bloque de ocho bytes.
   */
  private void decrypt(byte[] cipherText, int cipherOff, byte[] clearText, int clearOff) {
    squashBytesToShorts(cipherText, cipherOff, tempShorts, 0, 4);
    idea(tempShorts, tempShorts, decryptKeys);
    spreadShortsToBytes(tempShorts, 0, clearText, clearOff, 4);
  }

  /**
   * Reducir de short a bytes.
   */
  protected static void spreadShortsToBytes(int[] inShorts, int inOff, byte[] outBytes, int outOff,
      int shortLen) {
    for (int i = 0; i < shortLen; ++i) {
      outBytes[outOff + i * 2] = (byte) ((inShorts[inOff + i] >>> 8) & 0xff);
      outBytes[outOff + i * 2 + 1] = (byte) ((inShorts[inOff + i]) & 0xff);
    }
  }

  /**
   * Regenerar de bytes a short.
   */
  protected static void squashBytesToShorts(byte[] inBytes, int inOff, int[] outShorts, int outOff,
      int shortLen) {
    for (int i = 0; i < shortLen; ++i) {
      outShorts[outOff + i] =
          ((inBytes[inOff + i * 2] & 0xff) << 8) | ((inBytes[inOff + i * 2 + 1] & 0xff));
    }
  }
}