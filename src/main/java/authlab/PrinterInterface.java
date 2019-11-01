package authlab;

import java.io.FileNotFoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

public interface PrinterInterface extends Remote {

    public String print (String filename, String printer) throws RemoteException;
    public List<String> queue() throws RemoteException;
    public String topQueue(String job) throws RemoteException;
    public String start() throws RemoteException;
    public String stop() throws RemoteException;
    public String restart() throws RemoteException;
    public String status() throws RemoteException;
    public String readConfig(String parameter) throws RemoteException;
    public String setConfig(String parameter, String value) throws RemoteException;
    public String helpCommand() throws RemoteException;
    public byte[] convertAttemptedPassword (String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, RemoteException;
    public int login (byte[] username, byte[] attemptedPassword) throws RemoteException, FileNotFoundException;
}
