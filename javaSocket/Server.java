import java.io.DataInputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server{
    public static void main(String []args) throws Exception{
        ServerSocket socket = new ServerSocket(1105);
        Socket socket2 =  socket.accept();
        System.out.println("established");

        DataInputStream dis = new DataInputStream(socket2.getInputStream());
        int count = 0;
        while(count < 1000000){
            String  str=(String)dis.readUTF();
            System.out.println("message= "+str);
            count++;
        }
        socket2.close();
    }
}