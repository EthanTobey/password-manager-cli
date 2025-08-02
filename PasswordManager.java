import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Objects;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PasswordManager {
    private static final String fileName = "passwords.txt";
    private static boolean running = true;

    //check if password file exists
    private static boolean passwordFileExits() {
        String dirPath = "./";
        File file = new File(dirPath, fileName);
        return  (file.exists() && file.isFile());
    }

    //method to initialize user - called when creating new passwords file
    private static SecretKeySpec initializeUser(String newMasterPW) {  
        try {
            //generate salt
            SecureRandom random = new SecureRandom();   //use this to generate a Salt
            byte[] salt = new byte[16];
            random.nextBytes(salt);

            //generate key
            KeySpec spec = new PBEKeySpec(newMasterPW.toCharArray(), salt, 600000, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            SecretKey privateKey = factory.generateSecret(spec);
            SecretKeySpec aesKey = new SecretKeySpec(privateKey.getEncoded(), "AES");

            //encrypt token
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedToken = cipher.doFinal(newMasterPW.getBytes());

            //encode salt and token
            String saltEncoded = Base64.getEncoder().encodeToString(salt);
            String encryptedTokenEncoded = Base64.getEncoder().encodeToString(encryptedToken);

            //create passwords file, store salt and token to it
            File file = new File(fileName);
            file.createNewFile();
            try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(file))) {
                bufferedWriter.write(saltEncoded + ":" + encryptedTokenEncoded);
            }

            return aesKey;
        } 
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException |
                 BadPaddingException | InvalidKeySpecException | IOException e) {
            System.err.println("An error occurred while initializing user: " + e.getMessage());
            e.printStackTrace();
            quit();
            return null;   //if quitting, no key to return
        }
    }

    private static SecretKeySpec validateUser(String password) {
        try {
            //read salt and token from file
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName))) {
                String combinedLine = bufferedReader.readLine();
                String[] parts = combinedLine.split(":");
                String saltStringEncoded = parts[0];
                String tokenStringEncoded = parts[1];

                //decode salt and token
                byte[] salt = Base64.getDecoder().decode(saltStringEncoded);
                byte[] token = Base64.getDecoder().decode(tokenStringEncoded);

                //generate key from password
                KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600000, 128);
                SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey privateKey = factory.generateSecret(spec);
                SecretKeySpec aesKey = new SecretKeySpec(privateKey.getEncoded(), "AES");

                //decrypt token
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, aesKey);
                byte[] decryptedToken = cipher.doFinal(token);

                if (password.equals(new String(decryptedToken))) {
                    return aesKey;
                }
                else {
                    return null;
                }
            }
        } 
        catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException |
                NoSuchPaddingException | InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
            return null;
        }
    }

    //add password
    private static void addPassword(String label, String password, SecretKeySpec aesKey) {
        try {
            // Encrypt the new password
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encryptedPassword = cipher.doFinal(password.getBytes());

            // Encode the encrypted password
            String encodedPassword = Base64.getEncoder().encodeToString(encryptedPassword);

            // Read the file and check if the label exists
            StringBuilder fileContent = new StringBuilder();
            boolean labelFound = false;

            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName))) {
                String line;
                //append all lines of file to builder, modifying label's line with new password
                while ((line = bufferedReader.readLine()) != null) {
                    if (line.contains(label)) {
                        // If label found, replace it with the new password
                        fileContent.append(label).append(":").append(encodedPassword).append("\n");
                        labelFound = true;
                    } else {
                        // Otherwise, keep the current line
                        fileContent.append(line).append("\n");
                    }
                }
            } 

            // If the label was not found, append a new entry
            if (!labelFound) {
                fileContent.append(label).append(":").append(encodedPassword).append("\n");
            }

            // Write the updated content back to the file
            try (BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(fileName))) {
                bufferedWriter.write(fileContent.toString());
            } catch (IOException e) {
                System.err.println("Error writing to the file: " + e.getMessage());
            }

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException | IOException e) {
            System.err.println("An error occurred while adding password: " + e.getMessage());
            e.printStackTrace();
        }
    }


    //read password
    private static String readPassword(String label, SecretKeySpec aesKey) {
        try {
            //read file and look for label
            try (BufferedReader bufferedReader = new BufferedReader(new FileReader(fileName))) {
                String line;
                while ((line = bufferedReader.readLine()) != null) {
                    if (line.contains(label)) {
                        //found the label, break
                        break;
                    }
                }

                if (Objects.isNull(line)) return null;

                //get encrypted password
                String encryptedPassword = line.split(":")[1];

                //decode password
                byte[] decodedPassword = Base64.getDecoder().decode(encryptedPassword);

                //decrypt password
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, aesKey);
                byte[] decryptedPassword = cipher.doFinal(decodedPassword);

                return new String(decryptedPassword);
            }
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
             IllegalBlockSizeException | BadPaddingException | IOException e) {
            return null;
        }
    }

    //quit
    private static void quit() {
        running = false;
        System.exit(0);
    }

    //main method to run program
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        SecretKeySpec aesKey = null;  //aesKey not generated
        
        System.out.println("Welcome to Java Password Manager!");

        //check if password file exists
        if (passwordFileExits()) {
            //prompt for password
            System.out.println("Enter password: ");
            String enteredPassword = scanner.nextLine();

            //validate correct password and get key
            aesKey = validateUser(enteredPassword);
            if (Objects.isNull(aesKey)) {
                System.out.println("Passwords do not match. Exiting.");
                quit();
            }
        }
        else {
            System.out.println("No password file detected. Creating a new password file.");
            System.out.println("Enter new master password for user: ");
            aesKey = initializeUser(scanner.nextLine());
        }

        while (running) { 
            //prompt for add, read, quit
            System.out.println("a: Add Password \nr: Read Password \nq: Quit");
            System.out.println("Enter choice: ");
            switch (scanner.nextLine()) {
                case "a":
                    System.out.println("Enter label for password: ");
                    String label = scanner.nextLine();
                    System.out.println("Enter password to store: ");
                    addPassword(label, scanner.nextLine(), aesKey);
                    System.out.println();
                    break;
                case "r":
                    System.out.println("Enter label to read: ");
                    String returnedPassword = readPassword(scanner.nextLine(), aesKey);
                    if (Objects.isNull(returnedPassword))
                        System.out.println("No password exists for entered label");
                    else {
                        System.out.println("Found: " + returnedPassword + "\n");
                    }
                    break;
                case "q":
                    quit();
                    break;
                default:
                    System.out.println("Please enter valid input");
            }
        }

        scanner.close();
    }
}
