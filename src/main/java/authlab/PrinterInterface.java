package authlab;

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;

public interface PrinterInterface extends Remote {

    public String print (String filename, String printer) throws RemoteException;
    public List<String> queue() throws RemoteException;
    public void topQueue(int job) throws RemoteException;
    public String start() throws RemoteException;
    public String stop() throws RemoteException;
    public void restart() throws RemoteException;
    public String status() throws RemoteException;
    public String readConfig(String parameter) throws RemoteException;
    public void setConfig(String parameter, String value) throws RemoteException;
    public String helpCommand() throws RemoteException;
    public boolean login (String username, String password) throws  RemoteException;

}
