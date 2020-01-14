package isp.rsa;

import fri.isp.Agent;
import fri.isp.Environment;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

public class AgentCommunicationRSA {
    public static void main(String[] args) throws Exception {

        final KeyPair aliceKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        final KeyPair bobKP = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                /*
                - Create an RSA cipher and encrypt a message using Bob's PK;
                - Send the CT to Bob;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */

                byte[] pt = "Message to encrypt.".getBytes();
                final Cipher rsaEnc = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaEnc.init(Cipher.ENCRYPT_MODE, bobKP.getPublic());
                final byte[] ct = rsaEnc.doFinal(pt);

                print("ct1: " + hex(ct));
                send("bob", ct);

                /*String message = "message1";

                Signature rsaSha256Signature = Signature.getInstance("SHA256withRSA");
                rsaSha256Signature.initSign(aliceKP.getPrivate());
                rsaSha256Signature.update(message.getBytes());
                byte[] signed = rsaSha256Signature.sign();


                print("pt: " + hex(message.getBytes()));
                print("signed: " + hex(signed));*/

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {
                /*
                - Take the incoming message from the queue;
                - Create an RSA cipher and decrypt incoming CT using Bob's SK;
                - Print the message;
                - Reference the keys by using global variables aliceKP and bobKP.
                 */
                final byte[] ct = receive("alice");

                final Cipher rsaDec = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaDec.init(Cipher.DECRYPT_MODE, bobKP.getPrivate());
                final byte[] decryptedText = rsaDec.doFinal(ct);

                print("pt: " + new String(decryptedText));

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}
