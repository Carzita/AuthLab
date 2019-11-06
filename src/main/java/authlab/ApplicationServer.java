package authlab;

import java.io.IOException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class ApplicationServer {

    public static void main( String[] args ) throws IOException {
        Registry registry = LocateRegistry.createRegistry(5099);
        registry.rebind("printerAuthentication", new PrinterServant());
    }

}
