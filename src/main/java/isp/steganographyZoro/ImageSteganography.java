package isp.steganographyZoro;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.imageio.ImageIO;
//import javax.xml.bind.DatatypeConverter;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.BitSet;

/**
 * Assignments:
 * <p>
 * 1. Change the encoding process, so that the first 4 bytes of the steganogram hold the
 * length of the payload. Then modify the decoding process accordingly.
 * 2. Add security: Provide secrecy and integrity for the hidden message. Use GCM for cipher.
 * Also, use AEAD to provide integrity to the steganogram size.
 * 3. Extra: Enhance the capacity of the carrier:
 * -- Use the remaining two color channels;
 * -- Use additional bits.
 */
public class ImageSteganography {

    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message123".getBytes(StandardCharsets.UTF_8);

        /*ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded = ImageSteganography.decode("images/steganogram.png", payload.length + 4);
        System.out.println(Arrays.toString(decoded));
        System.out.printf("Decoded: %s%n", new String(decoded, StandardCharsets.UTF_8));
        */

        //TODO: Assignment 1

        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded1 = ImageSteganography.decode("images/steganogram.png");
        System.out.printf("Decoded: %s%n", new String(decoded1, "UTF-8"));


        // TODO: Assignment 2
        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        final byte[] initVector =  ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key, initVector);

        System.out.printf("Decoded: %s%n", new String(decoded2, "UTF-8"));
    }

    /**
     * Encodes given payload into the cover image and saves the steganogram.
     *
     * @param pt      The payload to be encoded
     * @param inFile  The filename of the cover image
     * @param outFile The filename of the steganogram
     * @throws IOException If the file does not exist, or the saving fails.
     */
    public static void encode(final byte[] pt, final String inFile, final String outFile) throws IOException {
        // load the image
        final BufferedImage image = loadImage(inFile);

        // Convert byte array to bit sequence
        final byte[] newPT = ByteBuffer.allocate(4 + pt.length).putInt(pt.length).put(pt).array();

        final BitSet bits = BitSet.valueOf(newPT); //sequence of bits....sequence of bits...

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
    }

    /**
     * Decodes the message from given filename.
     *
     * @param fileName The name of the file
     * @return The byte array of the decoded message
     * @throws IOException If the filename does not exist.
     */
    public static byte[] decode(final String fileName /*, int size*/) throws IOException {
        // load the image
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decode(image/*, size*/);

        // convert them to bytes
        return bits.toByteArray();
    }

    /**
     * Encrypts and encodes given plain text into the cover image and then saves the steganogram.
     *
     * @param pt      The plaintext of the payload
     * @param inFile  cover image filename
     * @param outFile steganogram filename
     * @param key     symmetric secret key
     * @throws Exception
     */
    public static byte[] encryptAndEncode(final byte[] pt, final String inFile, final String outFile, final Key key)
            throws Exception {
        // TODO
        final BufferedImage image = loadImage(inFile);

        // Convert byte array to bit sequence

        // pt = len(pt) + pt
        final Cipher aesGCM = Cipher.getInstance("AES/GCM/NoPadding");
        aesGCM.init(Cipher.ENCRYPT_MODE, key);
        byte[] encriptedPT = aesGCM.doFinal(pt);

        // System.out.println("encripted: " + Arrays.toString(encriptedPT) + " length: " + encriptedPT.length);

        final byte[] newPT = ByteBuffer.allocate(4 + encriptedPT.length).putInt(encriptedPT.length).put(encriptedPT).array();

        // System.out.println("new bits: " + Arrays.toString(newPT) + " [pt length ] " + pt.length);
        final BitSet bits = BitSet.valueOf(newPT); //sequence of bits....sequence of bits...

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        saveImage(outFile, image);
        return aesGCM.getIV();
    }

    /**
     * Decrypts and then decodes the message from the steganogram.
     *
     * @param fileName name of the steganogram
     * @param key      symmetric secret key
     * @return plaintext of the decoded message
     * @throws Exception
     */
    public static byte[] decryptAndDecode(final String fileName, final Key key, final byte[] initVector) throws Exception {
        // TODO
        final BufferedImage image = loadImage(fileName);

        // read all LSBs
        final BitSet bits = decode(image);

        byte[] cipherText = bits.toByteArray();
        Cipher aesGCM = Cipher.getInstance("AES/GCM/NoPadding");
        final GCMParameterSpec parameterSpec = new GCMParameterSpec(128, initVector);
        aesGCM.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        final byte[] ptMessage = aesGCM.doFinal(cipherText);

        // System.out.println("Decoded bits: " + Arrays.toString(bits.toByteArray()));
        // convert them to bytes
        return ptMessage;
    }

    /**
     * Loads an image from given filename and returns an instance of the BufferedImage
     *
     * @param inFile filename of the image
     * @return image
     * @throws IOException If file does not exist
     */
    protected static BufferedImage loadImage(final String inFile) throws IOException {
        return ImageIO.read(new File(inFile));
    }

    /**
     * Saves given image into file
     *
     * @param outFile image filename
     * @param image   image to be saved
     * @throws IOException If an error occurs while writing to file
     */
    protected static void saveImage(String outFile, BufferedImage image) throws IOException {
        ImageIO.write(image, "png", new File(outFile));
    }

    /**
     * Encodes bits into image. The algorithm modifies the least significant bit
     * of the red RGB component in each pixel.
     *
     * @param payload Bits to be encoded
     * @param image   The image onto which the payload is to be encoded
     */
    protected static void encode(final BitSet payload, final BufferedImage image) {
        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < payload.size(); x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < payload.size(); y++) {
                final Color original = new Color(image.getRGB(x, y));
               // System.out.println(original.getRed());
                // Let's modify the red component only
                final int newRed = payload.get(bitCounter) ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0


                // bitCounter++;
                // System.out.println(bitCounter+1);
                int newGreen = payload.get(bitCounter + 1) ?
                        original.getGreen() | 0x01:
                        original.getGreen() & 0xfe;

                // Create a new color object
                final Color modified = new Color(newRed, newGreen, original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(x, y, modified.getRGB());

                bitCounter +=2;
            }
        }
    }

    /**
     * Decodes the message from the steganogram
     *
     * @param image steganogram
     *
     * @return {@link BitSet} instance representing the sequence of read bits
     */
    protected static BitSet decode(final BufferedImage image/*, int size*/) {
        final BitSet bits = new BitSet();
        int sizeBits; //= 8 * size;

        BitSet bitSetSize = new BitSet();

        //calculate size....
        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < 32; x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < 32; y++) {
                final Color color = new Color(image.getRGB(x, y));
                final int lsb = color.getRed() & 0x01; // set everhing to bits....
                final int lsbG = color.getGreen() & 0x01;
                //System.out.println(lsb == 0x01);
                bitSetSize.set(bitCounter, lsb == 0x01);
                bitSetSize.set(bitCounter + 1, lsbG == 0x01);
                bitCounter += 2;
            }
        }
        int actualSize = ByteBuffer.wrap(bitSetSize.toByteArray()).getInt();
        // System.out.println("Size: " + Arrays.toString(bitSetSize.toByteArray()) + " int size: " + actualSize);

        sizeBits = 8 * actualSize;

        int bitTracking = 0;

        for (int x = image.getMinX(), bitCounter = 0; x < image.getWidth() && bitCounter < sizeBits; x++) {
            for (int y = image.getMinY(); y < image.getHeight() && bitCounter < sizeBits; y++) {

                if (bitTracking >= 32){
                    final Color color = new Color(image.getRGB(x, y));
                    int lsb = color.getRed() & 0x01; // set everhing to bits....
                    //System.out.println(lsb == 0x01);
                    bits.set(bitCounter, lsb == 0x01);

                    int lsbG = color.getGreen() & 0x01;
                    bits.set(bitCounter+1, lsbG == 0x01);

                    bitCounter +=2;
                }

                if (bitTracking < 32) {
                    bitTracking +=2;
                }
            }
        }

        return bits;
    }
}
