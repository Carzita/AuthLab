package authlab;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public interface PrinterInterface extends Remote {

    public String print (String filename, String printer) throws IOException;
    public List<String> queue() throws IOException;
    public String topQueue(String job) throws IOException;
    public String start() throws IOException;
    public String stop() throws IOException;
    public String restart() throws IOException;
    public String status() throws IOException;
    public String readConfig(String parameter) throws IOException;
    public String setConfig(String parameter, String value) throws IOException;
    public String helpCommand() throws IOException;
    public byte[] convertAttemptedPassword (String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, RemoteException;
    public int login (byte[] username, byte[] attemptedPassword) throws RemoteException, FileNotFoundException;
    public void writeToLogFile(String methodName) throws IOException;
    public void writeToLogFileFail(String methodName) throws IOException;
    public boolean checkAccessACL(String methodName) throws IOException;
    public boolean checkAccessRBAC(String methodName) throws IOException;
}
