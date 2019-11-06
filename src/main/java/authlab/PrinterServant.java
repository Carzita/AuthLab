package authlab;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.rmi.server.UnicastRemoteObject;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.sql.Timestamp;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class PrinterServant extends UnicastRemoteObject implements PrinterInterface {

    private boolean running = true;
    private List<String> printerQue = new ArrayList<>();
    private NumberFormat formatter = new DecimalFormat("0000");
    private String logUserName;

    protected PrinterServant() throws IOException {
        super();
    }

    @Override
    public void writeToLogFile(String methodName)throws IOException{
        Timestamp timestampLog = new Timestamp(System.currentTimeMillis());
        BufferedWriter buffLog = null;
        try {
            // true is set because we want to append data
            FileWriter fileWriter = new FileWriter("log.txt", true);
            buffLog = new BufferedWriter(fileWriter);
            buffLog.append("\r\n" + timestampLog + "," + logUserName +"," + methodName);
        } catch (IOException e) {
            System.err.println("Error with writeToLogFile: " + e.getMessage());
        } finally {
            if (buffLog != null) {
                buffLog.close();
            }
        }
    }

    @Override
    public String print(String filename, String printer) throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        if (running) {
            String jobNumber = formatter.format(printerQue.size() + 1);
            printerQue.add("<" + jobNumber + "> " + "<" + filename + ">");
            return "Printing file: " + filename + " on printer: " + printer;
        } else {
            return "Printer not running";
        }
    }

    @Override
    public List<String> queue() throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        return printerQue;
    }

    @Override
    public String topQueue(String job) throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        String noZero = job.replaceFirst("^0+(?!$)", "");
        int jobConverted = Integer.parseInt(noZero);
        try {
            return printerQue.get(jobConverted-1);
        } catch (IndexOutOfBoundsException e) {
            System.out.println(e);
            return "No job found";
        }
    }

    @Override
    public String start() throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
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
    public String stop() throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
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
    public String restart() throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        if(printerQue.isEmpty()) {
            return "queue is empty";
        } else {
            printerQue.clear();
            return "Cleared printer queue";
        }
    }

    @Override
    public String status() throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        return "Running status: " + running;
    }

    @Override
    public String readConfig(String parameter) throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        return "Fetched read config method from server with parameter: " + parameter;
    }

    @Override
    public String setConfig(String parameter, String value) throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
        return "Fetched setConfig method from server with parameter: " + parameter + "\n and value: " + value;
    }

    @Override
    public String helpCommand() throws IOException {
        writeToLogFile(Thread.currentThread().getStackTrace()[1].getMethodName());
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
    public int login(byte[] usernameEncrypted, byte[] attemptedPassword) {
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
                usernameDecryptedByte = aesCipher.doFinal(usernameEncrypted);
                usernameClear = new String(usernameDecryptedByte, StandardCharsets.UTF_8);

                if(compareUsername.equals(usernameClear)) {
                    // defining indexes to get the data from the file and getting the data
                    indexSalt = currentLine.indexOf(";");
                    lastIndex = currentLine.length();
                    saltString = currentLine.substring(indexUsername+1, indexSalt);
                    comparePW = currentLine.substring(indexSalt+1, lastIndex);

                    // decrypting password received from client and converting it to a string
                    // a string is necessary because the PBEKeySpec requires a char array
                    PWDecryptedByte = aesCipher.doFinal(attemptedPassword);
                    PWClear = new String(PWDecryptedByte, StandardCharsets.UTF_8);

                    // converting the strings into byte arrays
                    PWByte = Base64.getDecoder().decode(comparePW);
                    saltConvertedByte = Base64.getDecoder().decode(saltString);
                    // then hashing to be compared
                    attPWByte = convertAttemptedPassword(PWClear, saltConvertedByte);

                    // check for match
                    if(Arrays.equals(attPWByte, PWByte)) {
                        match = 1;
                        logUserName = usernameClear;

                    } else {
                        // password attempted does not match one stored in file
                        match = 0;
                    }
                } else {
                    // no username matched with the one inputted
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
