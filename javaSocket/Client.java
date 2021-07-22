import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Scanner;

public class Client {
    public static void main(String[] args) throws Exception{

        System.out.println("Server IP: ");
        Scanner scanner = new Scanner(System.in);
        String ip = scanner.next();

        Socket socket = new Socket(ip, 1105);

        System.out.println(socket.getLocalAddress());
        System.out.println(socket.getLocalPort());

        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        int count = 0;
        while(count < 1000000){
            count++;
            Thread.sleep(1000);
            dos.writeUTF("Message From client : " + count);
        }
//        String  str=(String)dis.readUTF();
//        System.out.println("message= "+str);
        socket.close();  
        
        // DataOutputStream dout=new DataOutputStream(socket.getOutputStream());  
        // dout.writeUTF("Hello Server");  
        // dout.flush();  
        // dout.close();  
        // socket.close();  
    }    
}
