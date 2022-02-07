import java.security.InvalidParameterException;

public class SPKeySchedule {
    public static final int keyLength = 16;

    public static byte[][] generateSubKeys(byte[] originalKey) throws InvalidParameterException {
        if (originalKey.length != SPKeySchedule.keyLength) {
            throw new InvalidParameterException("The original key should be equal to " + SPKeySchedule.keyLength);
        }

        byte[][] result = new byte[SPKeySchedule.keyLength + 1][SPKeySchedule.keyLength];
        result[0] = originalKey;

        byte[][] intermediateResult = new byte[SPKeySchedule.keyLength + 1][SPKeySchedule.keyLength + 1];
        byte sum = 0;
        for (int i = 0; i < originalKey.length; i++) {
            sum = (byte) (sum ^ originalKey[i]);
            intermediateResult[0][i] = originalKey[i];
        }
        intermediateResult[0][SPKeySchedule.keyLength] = sum;

        for (int i = 1; i <= SPKeySchedule.keyLength; i++) {
            for (int j = 0; j < intermediateResult[i].length; j++) {
                byte value = intermediateResult[i - 1][j];
                value = rotateLeft(value, 3);
                intermediateResult[i][j] = value;
            }
        }

        for (int i = 1; i < SPKeySchedule.keyLength + 1; i++) {
            for (int j = 0; j < SPKeySchedule.keyLength; j++) {
                int index = (i + j) % intermediateResult[i].length;
                byte biasWord = SPConstants.BiasWords[i - 1][j];
                byte value = intermediateResult[i][index];
                value = (byte) (value + biasWord);
                result[i][j] = value;
            }
        }

        return result;
    }

    private static byte rotateLeft(byte bits, int shift) {
        return (byte) (((bits & 0xff) << shift) | ((bits & 0xff) >>> (8 - shift)));
    }
}
