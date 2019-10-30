package authlab;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.rmi.MarshalException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Client
{
    public static void main( String[] args ) throws NotBoundException, MalformedURLException, RemoteException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // declaring
        String username, password, input, filename, printer;
        byte[] usernameByte, ciphertextUN, passwordByte, ciphertextPW;

        PrinterInterface service = (PrinterInterface) Naming.lookup("rmi://localhost:5099/printerTest");
        Scanner myScanner = new Scanner(System.in);

        // initializing cipher values
        String staticSharedKey = "XupwNQ3MFPcj/F/S1KOpDA==";
        // decode the base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(staticSharedKey);
        // build key using SecretKeySpec
        SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

        while (true) {
            try {
            System.out.println("Enter Username");
            username = myScanner.nextLine();
            // converting username to byte array and encrypting it
            usernameByte = username.getBytes();
            ciphertextUN = aesCipher.doFinal(usernameByte);

            System.out.println("Enter password");
            password = myScanner.nextLine();
            // converting password to byte array and encrypting it
            passwordByte = password.getBytes();
            ciphertextPW = aesCipher.doFinal(passwordByte);

                if(service.login(ciphertextUN, ciphertextPW) == 1) {
                    break;
                } else {
                    System.out.println("Wrong username or password, try again");
                }
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }
        }

        loop: while (true) {
            System.out.println("Enter command, enter help for a list over commands");
            input = myScanner.nextLine();

            switch (input.toLowerCase()) {
                case "help":
                    System.out.println(service.helpCommand());
                    break;
                case "print":
                    System.out.println("Enter filename");
                    filename = myScanner.nextLine();
                    System.out.println("Enter printer");
                    printer = myScanner.nextLine();
                    System.out.println(service.print(filename, printer));
                    break;
                case "queue":
                    System.out.println("<Job number> <File name>");
                    service.queue().forEach(System.out::println);
                    break;
                case "topqueue":
                    System.out.println("Enter job you want to be moved to top of the queue");
                    if (myScanner.hasNextInt()) {
                        int job = myScanner.nextInt();
                        service.topQueue(job);
                        break;
                    } else {
                        System.out.println("Only numbers accepted");
                        myScanner.nextLine();
                    }
                    break;
                case "start":
                    System.out.println(service.start());
                    break;
                case "stop":
                    System.out.println(service.stop());
                    break;
                case "restart":
                    service.restart();
                    break;
                case "status":
                    System.out.println(service.status());
                    break;
                case "readconfig":
//                    service.readConfig();
                    System.out.println(service.readConfig("lol"));
                    break;
                case "setconfig":
//                    service.setConfig();
                    System.out.println("tba2");
                case "exit":
                    break loop;
                default:
                    System.out.println("Unknown command, type 'help' for list over commands");
            }
        }
    }
}
