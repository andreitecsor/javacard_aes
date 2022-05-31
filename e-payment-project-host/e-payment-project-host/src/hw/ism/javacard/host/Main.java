package hw.ism.javacard.host;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadClientInterface;
import com.sun.javacard.apduio.CadDevice;
import com.sun.javacard.apduio.CadTransportException;

import java.io.IOException;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 9025)) {
            CadClientInterface cadClientInstance = CadDevice.getCadClientInstance(CadDevice.PROTOCOL_T1, socket.getInputStream(), socket.getOutputStream());
            Apdu apdu = new Apdu();
            // SELECT APPLET
            apdu.command = new byte[]{(byte) 0x00, (byte) 0xA4, 0x04, 0x00};
            apdu.setDataIn(new byte[]{(byte) 0xA1, (byte) 0xA2, (byte) 0xB3, (byte) 0xC4, (byte) 0xD5, 0x01, 0x01},
                           7); //length can be omitted,
            apdu.setLe(0x7f);
            cadClientInstance.powerUp();
            cadClientInstance.exchangeApdu(apdu);

            //CHECK PIN OPERATION
            apdu.command = new byte[]{(byte) 0x80, 0x01, 0x00, 0x00};
            apdu.setDataIn(new byte[]{(byte) 0x4D, 0x59, 0x38, 0x43, 0x48, 0x41, 0x52, 0x50}); // PIN VALUE: MY8CHARP
            cadClientInstance.exchangeApdu(apdu);

            //AES ENCRYPT OPERATION
            byte[] message = Files.readAllBytes(Path.of("Message.txt"));
            apdu.command = new byte[]{(byte) 0x80, 0x02, 0x00, 0x00};
            apdu.setDataIn(message);
            cadClientInstance.exchangeApdu(apdu);
            byte[] encryptedMessage = apdu.getDataOut();

            //AES DECRYPT OPERATION
            apdu.command = new byte[]{(byte) 0x80, 0x03, 0x00, 0x00};
            apdu.setDataIn(encryptedMessage);
            cadClientInstance.exchangeApdu(apdu);
            byte[] decryptedMessage = apdu.getDataOut();

            if (Arrays.equals(message, decryptedMessage)) {
                System.out.println("AES ENCRYPTION/DECRYPTION SUCCEEDED");
            }

        } catch (IOException | CadTransportException e) {
            throw new RuntimeException(e);
        }
    }
}
