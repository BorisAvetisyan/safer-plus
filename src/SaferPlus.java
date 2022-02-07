import java.util.Arrays;

public class SaferPlus {
    public static void main(String[] args) {
        byte[] plaintext = {(byte) 179, (byte) 166, (byte) 219, 60, (byte) 135, 12, 62, (byte) 153, 36, 94, 13, 28, 6, (byte) 183, 71, (byte) 222};
        byte[] key = {41, 35, (byte) 190, (byte) 132, (byte) 225, 108, (byte) 214, (byte) 174, 82, (byte) 144, 73, (byte) 241, (byte) 241, (byte) 187, (byte) 233, (byte) 235};
        int[] ciphertextOutput = encrypt(plaintext, key);
        byte [] ciphertext = new byte[ciphertextOutput.length];
        for (int i = 0; i < ciphertextOutput.length; i++) {
            ciphertext[i] = (byte) ciphertextOutput[i];
        }
        byte[] decryptedOutput = decrypt(ciphertext, key);
        System.out.println("Encrypted output is " + Arrays.toString(ciphertextOutput));
        System.out.println("Decrypted output is " + Arrays.toString(decryptedOutput));
    }

    public static int[] encrypt(byte[] plaintext, byte[] key) {
        byte[][] subKeys = SPKeySchedule.generateSubKeys(key);
        byte[] result = new byte[plaintext.length];
        System.arraycopy(plaintext, 0, result, 0, plaintext.length);

        result = round(result, subKeys);

        byte[] cipherText = additionalRounds(result, subKeys);

        int[] finalResult = new int[result.length];
        for (int i = 0; i < cipherText.length; i++) {
            if(cipherText[i] < 0) {
                finalResult[i] = cipherText[i] + 256;
            } else {
                finalResult[i] = cipherText[i];
            }
        }
        return finalResult;
    }

    private static byte[] additionalRounds(byte[] result, byte[][] subKeys) {
        for (int index : SPConstants.additionRoundIndices) {
            result[index] = (byte) (result[index] ^ subKeys[16][index]);
        }
        for (int index : SPConstants.modAdditionRoundIndices) {
            result[index] = (byte) (result[index] + subKeys[16][index]);
        }
        return result;
    }

    private static byte[] round(byte[] result, byte[][] subKeys) {
        for (int i = 0; i < 8; i++) {
            byte[] subKey1 = subKeys[2 * i];
            byte[] subKey2 = subKeys[2 * i + 1];

            for (int index : SPConstants.additionRoundIndices) {
                result[index] = (byte) (result[index] ^ subKey1[index]);
                result[index] = (byte) (modPow(result[index]));
                result[index] = (byte) (result[index] + subKey2[index]);
            }
            for (int index : SPConstants.modAdditionRoundIndices) {
                result[index] = (byte) (result[index] + subKey1[index]);
                result[index] = (byte) (log(result[index]));
                result[index] = (byte) (result[index] ^ subKey2[index]);
            }

            byte[] newResult = new byte[result.length];
            for (int j = 0; j < result.length; j++) {
                newResult[j] = multiplyWithM(result, j);
            }
            result = newResult;
        }
        return result;
    }

    public static byte[] decrypt(byte[] ciphertext, byte[] key) {
        byte[][] subKeys = SPKeySchedule.generateSubKeys(key);
        byte[] result = new byte[ciphertext.length];
        System.arraycopy(ciphertext, 0, result, 0, ciphertext.length);

        for (int index : SPConstants.additionRoundIndices) { // 1, 2, 5, 6, 9, 10, 13, 14
            result[index] = (byte) (result[index] ^ subKeys[16][index]);
        }
        for (int index : SPConstants.modAdditionRoundIndices) { // 1, 2, 5, 6, 9, 10, 13, 14
            result[index] = (byte) (result[index] - subKeys[16][index]);
        }

        for (int i = 7; i >= 0; i--) {
            byte[] subKey1 = subKeys[2 * i + 1];
            byte[] subKey2 = subKeys[2 * i];

            byte[] newResult = new byte[result.length];
            for (int j = 0; j < result.length; j++) {
                newResult[j] = multiplyWithMInverse(result, j);
            }
            result = newResult;

            for (int index : SPConstants.additionRoundIndices) { // 1, 2, 5, 6, 9, 10, 13, 14
                result[index] = (byte) (result[index] - subKey1[index]);
                result[index] = (byte) (log(result[index]));
                result[index] = (byte) (result[index] ^ subKey2[index]);
            }
            for (int index : SPConstants.modAdditionRoundIndices) { // 1, 2, 5, 6, 9, 10, 13, 14
                result[index] = (byte) (result[index] ^ subKey1[index]);
                result[index] = (byte) (modPow(result[index]));
                result[index] = (byte) (result[index] - subKey2[index]);
            }
        }

        return result;
    }

    private static byte multiplyWithM(byte[] output, int index) {
        byte result = 0;
        for (int i = 0; i < SPConstants.M.length; i++) {
            byte m = SPConstants.M[i][index];
            result = (byte) (result + (m * output[i]));
        }
        return result;
    }

    private static byte multiplyWithMInverse(byte[] output, int index) {
        byte result = 0;
        for (int i = 0; i < SPConstants.M_Inverse.length; i++) {
            byte m = SPConstants.M_Inverse[i][index];
            result = (byte) (result + m * output[i]);
        }
        return result;
    }

    private static int modPow(byte pow) {
        if (pow == -128) {
            return 0;
        }
        int power = pow;
        if (power < 0) {
            power += 256;
        }

        int result = 45;
        for (int i = 2; i <= power; i++) {
            result = result * 45;
            result = result % 257;
        }
        return result;
    }

    private static int log(int val) {
        if (val == 0) {
            return 128;
        }
        int value = val;
        if (value < 0) {
            value += 256;
        }

        for (int i = 0; i <= 256; i++) {
            if (modPow((byte) i) == value) {
                return i;
            }
        }
        return -1;
    }
}
