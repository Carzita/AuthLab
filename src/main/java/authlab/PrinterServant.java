package authlab;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class PrinterServant extends UnicastRemoteObject implements PrinterInterface {

    private boolean running = true;
    private List<String> printerQue = new ArrayList<>();
    //    public ArrayList<queList> printerQueClass = new ArrayList<queList>();
    private NumberFormat formatter = new DecimalFormat("0000");

    // initializing values to decrypt / encrypt strings passed between client and server


    protected PrinterServant() throws RemoteException {
        super();
    }

/*    static class queList {
        String jobNumber;
        String fileName;

        public queList(String jobNumber, String fileName) {
            this.jobNumber = jobNumber;
            this.fileName = fileName;
        }
    }*/

    @Override
    public String print(String filename, String printer) {
        if (running) {
            String jobNumber = formatter.format(printerQue.size() + 1);
//            printerQueClass.add(new queList(jobNumber, filename));
            printerQue.add("<" + jobNumber + "> " + "<" + filename + ">");
            return "Printing file: " + filename + " on printer: " + printer;
        } else {
            return "Printer not running";
        }
    }

    @Override
    public List<String> queue() {
        return printerQue;
    }

/*    @Override
    public ArrayList<queList> queue() throws RemoteException {
        return printerQueClass;
    }*/

    @Override
    public void topQueue(int job) {
//        printerQue.add(0, job );
    }

    @Override
    public String start() {
        if(!running) {
            running = true;
            System.out.println("Printer starting");
            return "Starting printer";
        } else {
            System.out.println("Printer already running");
            return "Printer already running";
        }
    }

    @Override
    public String stop() {
        if(running) {
            running = false;
            System.out.println("Printer stopping");
            return "Stopping printer";
        } else {
            System.out.println("Printer already not running");
            return "Printer already not running";
        }
    }

    @Override
    public void restart() {
        printerQue.clear();
    }

    @Override
    public String status() {
        return "Running status: " + running;
    }

    @Override
    public String readConfig(String parameter) {
        return ("Working Directory = " + System.getProperty("user.dir"));
    }

    @Override
    public void setConfig(String parameter, String value) {

    }

    @Override
    public String helpCommand() {
        return "List over commands:" +
                "\nPrint" +
                "\nQueue" +
                "\nTopQueue" +
                "\nStart" +
                "\nStop" +
                "\nRestart" +
                "\nStatus" +
                "\nReadconfig" +
                "\nSetconfig";
    }

    @Override
    public byte[] convertAttemptedPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        return factory.generateSecret(spec).getEncoded();
    }


    @Override
    public int login(byte[] usernameEncypted, byte[] attemptedPassword) {
        try {
            // declaring
            String staticSharedKey, currentLine, compareUsername, saltString, comparePW, usernameClear, PWClear;
            int match = 0, indexUsername, indexSalt, lastIndex;
            byte[] decodedKeyByte, usernameDecryptedByte, PWDecryptedByte, PWByte, saltConvertedByte, attPWByte;

            FileReader fileReader = new FileReader("users.txt");
            BufferedReader bufReader = new BufferedReader(fileReader);

            // initializing cipher values
            staticSharedKey = "XupwNQ3MFPcj/F/S1KOpDA==";
            // decode the base64 encoded string
            decodedKeyByte = Base64.getDecoder().decode(staticSharedKey);
            // build key using SecretKeySpec
            SecretKey aesKey = new SecretKeySpec(decodedKeyByte, 0, decodedKeyByte.length, "AES");
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

            while((currentLine = bufReader.readLine()) != null && match != 1) {
                indexUsername = currentLine.indexOf(",");
                compareUsername = currentLine.substring(0,indexUsername);

                // decrypting username received from client and converting it to a string
                usernameDecryptedByte = aesCipher.doFinal(usernameEncypted);
                usernameClear = new String(usernameDecryptedByte, StandardCharsets.UTF_8);

                if(compareUsername.equals(usernameClear)) {
                    // defining indexes to get the data from the file and getting the data
                    indexSalt = currentLine.indexOf(";");
                    lastIndex = currentLine.length();
                    saltString = currentLine.substring(indexUsername+1, indexSalt);
                    comparePW = currentLine.substring(indexSalt+1, lastIndex);

                    // decrypting password received from client and converting it to a string
                    PWDecryptedByte = aesCipher.doFinal(attemptedPassword);
                    PWClear = new String(PWDecryptedByte, StandardCharsets.UTF_8);

                    // converting the strings into byte arrays for comparison
                    PWByte = Base64.getDecoder().decode(comparePW);
                    saltConvertedByte = Base64.getDecoder().decode(saltString);
                    attPWByte = convertAttemptedPassword(PWClear, saltConvertedByte);

                    // check for match
                    if(Arrays.equals(attPWByte, PWByte)) {
                        match = 1;

                    } else {
                        System.out.println("wrong password");
                        match = 0;
                    }
                } else {
                    System.out.println("wrong username");
                    match = 0;
                }
            }
            fileReader.close();
            return match;
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return 0;
    }

}
