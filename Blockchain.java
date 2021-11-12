import java.util.ArrayList;
import java.util.Date;
import java.security.MessageDigest;

public class Blockchain {

    public static ArrayList<Block> blockchain = new ArrayList<Block>();

    public static void main(String[] args) {
        blockchain.add(new Block("First block", "0"));
        blockchain.add(new Block("Second block", blockchain.get(blockchain.size() - 1).hash));
        blockchain.add(new Block("Third block", blockchain.get(blockchain.size() - 1).hash));
        blockchain.add(new Block("Fourth block", blockchain.get(blockchain.size() - 1).hash));
        blockchain.add(new Block("Fifth block", blockchain.get(blockchain.size() - 1).hash));
    }

    public static Boolean isChainValid() {
        Block currentBlock;
        Block previousBlock;

        for (int i = 1; i < blockchain.size(); i++) {

            currentBlock = blockchain.get(i);
            previousBlock = blockchain.get(i - 1);

            if (!currentBlock.hash.equals(currentBlock.calculateHash())) {
                System.out.println("Hashes are not equal");
                return false;
            }

            if (!previousBlock.hash.equals(currentBlock.previousHash)) {
                System.out.println("Previous Hashes are not equal");
                return false;
            }
        }
        return true;
    }
}

class Block {

    public String hash;
    public String previousHash;
    private String data;
    private long timeStamp;

    public Block(String data, String previousHash) {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = new Date().getTime();
        this.hash = calculateHash();
    }

    public String calculateHash() {
        String calculatedhash = crypt.sha256(previousHash + Long.toString(timeStamp) + data);
        return calculatedhash;
    }
}

class crypt {

    public static String sha256(String input) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            int i = 0;
            byte[] hash = sha.digest(input.getBytes("UTF-8"));

            StringBuffer hexHash = new StringBuffer();

            while (i < hash.length) {
                String hex = Integer.toHexString(0xff & hash[i]);
                if (hex.length() == 1)
                    hexHash.append('0');
                hexHash.append(hex);
                i++;
            }
            return hexHash.toString();
        }
        catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
