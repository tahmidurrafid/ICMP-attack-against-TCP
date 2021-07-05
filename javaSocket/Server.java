import java.io.DataInputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server{
    public static void main(String []args) throws Exception{
        ServerSocket socket = new ServerSocket(1020);
        Socket socket2 =  socket.accept();
        System.out.println("established");

        DataInputStream dis = new DataInputStream(socket2.getInputStream());  
        String  str=(String)dis.readUTF();  
        System.out.println("message= "+str);  
        socket2.close();  
    }
}