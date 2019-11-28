package authlab;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
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
    private int userID;

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

    // check user access via ACL
    @Override
    public boolean checkAccessACL(String methodName) throws IOException {
        System.out.println("Checking access via ACL on user: " + userID + " on method: " + methodName);
        FileReader fileReader;
        BufferedReader bufReader;
        int match = 0;
               /*  switch depending on which method method access file is requested, userID is saved on server when
               user logs in so is therefore not part of the method parameters from client*/
        switch(methodName) {
            case "print":
                fileReader = new FileReader("ACL/0print.txt");
                bufReader = new BufferedReader(fileReader);
                // checking for this printer function if user has access via getPermissionACL method
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "queue":
                fileReader = new FileReader("ACL/1queue.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "topqueue":
                fileReader = new FileReader("ACL/2topqueue.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "start":
                fileReader = new FileReader("ACL/3start.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "stop":
                fileReader = new FileReader("ACL/4stop.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "restart":
                fileReader = new FileReader("ACL/5restart.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "status":
                fileReader = new FileReader("ACL/6status.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "readconfig":
                fileReader = new FileReader("ACL/7readconfig.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            case "setconfig":
                fileReader = new FileReader("ACL/8setconfig.txt");
                bufReader = new BufferedReader(fileReader);
                match = getPermissionACL(userID, bufReader, match);
                bufReader.close();
                fileReader.close();
                break;
            default:
                System.out.println("Unknown command, type 'help' for list over commands");
        }
        return match == 1;
    }

    private int getPermissionACL(int userID, BufferedReader bufReader, int match) throws IOException {
        String lineFromACL;
        // while there is no match and still lines left
        while((lineFromACL = bufReader.readLine()) != null && match != 1) {
            int i = Integer.parseInt(lineFromACL.substring(0,1));
            if(i==userID){
                // check if access is equal to T (true)
                if(lineFromACL.substring(2).equals("T")) {
                    match = 1;
                } else {
                    match = 0;
                    // user does not have access, breaking while loop
                    break;
                }
            } else {
                match = 0;
            }
        }
        // return permission
        return match;
    }

    // check user access via RBAC
    public boolean checkAccessRBAC(String methodName) throws IOException {
        System.out.println("Checking access via RBAC on user: " + userID + " on method: " + methodName);
        FileReader fileReader;
        BufferedReader bufReader;
        int match = 0;
        fileReader = new FileReader("RBAC/role.txt");
        bufReader = new BufferedReader(fileReader);
        String lineFromRBACrole, role = null;
        // retrieving user role from role.txt according to userID
        while((lineFromRBACrole = bufReader.readLine()) != null && match != 1) {
            int i = Integer.parseInt(lineFromRBACrole.substring(0,1));
            if(i==userID){
                role = lineFromRBACrole.substring(2);
                match = 1;
                System.out.println("User id found and is: " + userID + " and is assigned role: " + role );
            } else {
                match = 0;
            }
        }
        fileReader.close();
        if(match==1){
            boolean privilege = false;
            // getting line of role privileges to be checked in getMatchRBAC method
            switch(role) {
                case "manager":
                    String managerAccess = Files.readAllLines(Paths.get("RBAC/access.txt")).get(0);
                    privilege = getPrivilegeRBAC(managerAccess, methodName);
                    break;
                case "janitor":
                    String janitorAccess = Files.readAllLines(Paths.get("RBAC/access.txt")).get(1);
                    privilege = getPrivilegeRBAC(janitorAccess, methodName);
                    break;
                case "poweruser":
                    String poweruserAccess = Files.readAllLines(Paths.get("RBAC/access.txt")).get(2);
                    privilege = getPrivilegeRBAC(poweruserAccess, methodName);
                    break;
                case "user":
                    String userAccess = Files.readAllLines(Paths.get("RBAC/access.txt")).get(3);
                    privilege = getPrivilegeRBAC(userAccess, methodName);
                    break;
                default:
                    System.out.println("Unknown user role, contact IT for support");
            }
            // returning if the user role has access to the requested method
            return privilege;
        } else {
            System.out.println("The userID does not match with any role");
            return false;
        }
    }

    public boolean getPrivilegeRBAC(String userAccess, String methodName) throws IOException {
        int indexRoleEnd = userAccess.indexOf(",");
        boolean access = false;
        switch(methodName) {
/*           checking if role has access to the method which is done by checking according to index if it's T(true) in access file.
             In the access file the T's are sorted in order of appearance (same order as ACL files)*/
            case "print":
                access = (userAccess.substring(indexRoleEnd+1, indexRoleEnd+2).equals("T"));
                break;
            case "queue":
                access = (userAccess.substring(indexRoleEnd+3, indexRoleEnd+4).equals("T"));
                break;
            case "topqueue":
                access = (userAccess.substring(indexRoleEnd+5, indexRoleEnd+6).equals("T"));
                break;
            case "start":
                access = (userAccess.substring(indexRoleEnd+7, indexRoleEnd+8).equals("T"));
                break;
            case "stop":
                access = (userAccess.substring(indexRoleEnd+9, indexRoleEnd+10).equals("T"));
                break;
            case "restart":
                access = (userAccess.substring(indexRoleEnd+11, indexRoleEnd+12).equals("T"));
                break;
            case "status":
                access = (userAccess.substring(indexRoleEnd+13, indexRoleEnd+14).equals("T"));
                break;
            case "readconfig":
                access = (userAccess.substring(indexRoleEnd+15, indexRoleEnd+16).equals("T"));
                break;
            case "setconfig":
                access = (userAccess.substring(indexRoleEnd+17).equals("T"));
                break;
            default:
                System.out.println("Unknown methodname parsed");
        }
        return access;
    }

    @Override
    public int login(byte[] usernameEncrypted, byte[] attemptedPassword) {
        try {
            // declaring
            String staticSharedKey, currentLine, compareUsername, saltString, comparePW, usernameClear, PWClear;
            int match = 0, indexUsername, indexSalt, lastIndex, indexID;
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
                indexID = currentLine.indexOf(":");

                compareUsername = currentLine.substring(indexID+1,indexUsername);

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
                        userID = Integer.parseInt(currentLine.substring(0, 1));

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
