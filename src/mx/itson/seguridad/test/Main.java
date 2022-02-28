package mx.itson.seguridad.test;

import mx.itson.seguridad.criptografia.algoritmo.IDEA;

public class Main {

  public static void main(String[] args) {

    String toEncrypt = "Seguridad informatica 2020";//90123";

    String key = "diegocastro";
    IDEA idea = new IDEA(key);

    String encrypted = idea.encrypt(toEncrypt);
    String decrypted = idea.decrypt(encrypted);

    System.out.println("Llave                     : " + key);
    System.out.println("Mensaje                   : " + toEncrypt);
    System.out.println("Mensaje Encriptado        : " + encrypted);
    System.out.println("Mensaje Desencriptado     : " + decrypted);
  }
}