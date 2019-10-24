package authlab;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;

public class PrinterServant extends UnicastRemoteObject implements PrinterInterface {

    private boolean running = true;
    private List<String> printerQue = new ArrayList<>();
//    public ArrayList<queList> printerQueClass = new ArrayList<queList>();
    private NumberFormat formatter = new DecimalFormat("0000");


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
    public String print(String filename, String printer) throws RemoteException {
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
    public List<String> queue() throws RemoteException {
        return printerQue;
    }

/*    @Override
    public ArrayList<queList> queue() throws RemoteException {
        return printerQueClass;
    }*/

    @Override
    public void topQueue(int job) throws RemoteException {
//        printerQue.add(0, job );
    }

    @Override
    public String start() throws RemoteException {
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
    public String stop() throws RemoteException {
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
    public void restart() throws RemoteException {
        printerQue.clear();
    }

    @Override
    public String status() throws RemoteException {
        return "Running status: " + running;
    }

    @Override
    public String readConfig(String parameter) throws RemoteException {
        return ("Working Directory = " + System.getProperty("user.dir"));
    }

    @Override
    public void setConfig(String parameter, String value) throws RemoteException {

    }

    @Override
    public String helpCommand() throws RemoteException {
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
    public int login(String username, String password) throws RemoteException, FileNotFoundException {
        try {
            FileReader fileReader = new FileReader("users.txt");
            BufferedReader bufReader = new BufferedReader(fileReader);
            String currentLine, compare, compare2;
            int index, lastIndex;
            int match = 0;

            while((currentLine = bufReader.readLine()) != null && match != 1) {
                index = currentLine.indexOf(",");
                compare = currentLine.substring(0,index);
                System.out.println("username from file: " + compare);
                if(compare.equals(username)) {
                    lastIndex = currentLine.length();
                    compare2 = currentLine.substring(index+1, lastIndex);
                    System.out.println("password from file: " + compare2);
                    if(compare2.equals(password)) {
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
