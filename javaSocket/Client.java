import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;

public class Client {
    public static void main(String[] args) throws Exception{
        Socket socket = new Socket("127.0.0.1", 1020);

        System.out.println(socket.getLocalAddress());
        System.out.println(socket.getLocalPort());

        DataInputStream dis = new DataInputStream(socket.getInputStream());  
        String  str=(String)dis.readUTF();  
        System.out.println("message= "+str);  
        socket.close();  
        
        // DataOutputStream dout=new DataOutputStream(socket.getOutputStream());  
        // dout.writeUTF("Hello Server");  
        // dout.flush();  
        // dout.close();  
        // socket.close();  
    }    
}
