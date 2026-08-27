package hermesloader.parser;

public class BitBufferReader {
    private final byte[] buf;
    private int bytePos;
    private int bitPos;

    public BitBufferReader(byte[] buf) {
        this(buf, 0, 0);
    }

    public BitBufferReader(byte[] buf, int bytePos, int bitPos) {
        this.buf = buf;
        this.bytePos = bytePos;
        this.bitPos = bitPos;
    }

    public int readBits(int bits) {
        int result = 0;
        for (int i = 0; i < bits; i++) {
            int currentByte = buf[bytePos] & 0xFF;
            int bit = (currentByte >> bitPos) & 1;
            result |= (bit << i);

            bitPos++;
            if (bitPos == 8) {
                bitPos = 0;
                bytePos++;
            }
        }
        return result;
    }

    public int readByte() {
        if (bitPos != 0) {
            throw new RuntimeException("Unaligned byte read");
        }
        int val = buf[bytePos] & 0xFF;
        bytePos++;
        return val;
    }

    public int readUInt16() {
        if (bitPos != 0) {
            throw new RuntimeException("Unaligned byte read");
        }
        int val = ((buf[bytePos] & 0xFF) | ((buf[bytePos + 1] & 0xFF) << 8));
        bytePos += 2;
        return val;
    }

    public int readUInt32() {
        if (bitPos != 0) {
            throw new RuntimeException("Unaligned byte read");
        }
        int val = ((buf[bytePos] & 0xFF) |
                  ((buf[bytePos + 1] & 0xFF) << 8) |
                  ((buf[bytePos + 2] & 0xFF) << 16) |
                  ((buf[bytePos + 3] & 0xFF) << 24));
        bytePos += 4;
        return val;
    }

    public long readUInt64() {
        if (bitPos != 0) {
            throw new RuntimeException("Unaligned byte read");
        }
        long val = ((buf[bytePos] & 0xFF) |
                   ((long)(buf[bytePos + 1] & 0xFF) << 8) |
                   ((long)(buf[bytePos + 2] & 0xFF) << 16) |
                   ((long)(buf[bytePos + 3] & 0xFF) << 24) |
                   ((long)(buf[bytePos + 4] & 0xFF) << 32) |
                   ((long)(buf[bytePos + 5] & 0xFF) << 40) |
                   ((long)(buf[bytePos + 6] & 0xFF) << 48) |
                   ((long)(buf[bytePos + 7] & 0xFF) << 56));
        bytePos += 8;
        return val;
    }

    public byte[] readBytes(int length) {
        if (bitPos != 0) {
            throw new RuntimeException("Unaligned byte read");
        }
        byte[] val = new byte[length];
        System.arraycopy(buf, bytePos, val, 0, length);
        bytePos += length;
        return val;
    }

    public int getBytePos() {
        return bytePos;
    }

    public int getBitPos() {
        return bitPos;
    }
}
