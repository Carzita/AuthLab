package authlab;

import java.io.FileNotFoundException;
import java.net.MalformedURLException;
import java.rmi.MarshalException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.util.Scanner;

public class Client
{
    public static void main( String[] args ) throws NotBoundException, MalformedURLException, RemoteException {
        PrinterInterface service = (PrinterInterface) Naming.lookup("rmi://localhost:5099/printerTest");
        Scanner myScanner = new Scanner(System.in);

        while (true) {
            System.out.println("Enter Username");
            String username = myScanner.nextLine();
            System.out.println("Enter password");
            String password = myScanner.nextLine();
            try {
                if(service.login(username, password) == 1) {
                    break;
                }
            } catch (FileNotFoundException e) {
                System.out.println(e);
            }
        }

        loop: while (true) {
            System.out.println("Enter command, enter help for a list over commands");
            String input = myScanner.nextLine();

            switch (input.toLowerCase()) {
                case "help":
                    System.out.println(service.helpCommand());
                    break;
                case "print":
                    System.out.println("Enter filename");
                    String filename = myScanner.nextLine();
                    System.out.println("Enter printer");
                    String printer = myScanner.nextLine();
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
                    System.out.println("tba");
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
