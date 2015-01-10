package sos.passportapplet;

/**
 * A very rough, zero extra memory use, TLV array scanner.
 * 
 * @author Cees-Bart Breunesse <ceesb@cs.ru.nl>
 * @author Wojciech Mostowski <woj@cs.ru.nl>
 *
 */
public class BERTLVScanner {

    /** Universal tag class. */
    public static final short UNIVERSAL_CLASS = 0;
    /** Application tag class. */
    public static final short APPLICATION_CLASS = 1;
    /** Context specific tag class. */
    public static final short CONTEXT_SPECIFIC_CLASS = 2;
    /** Private tag class. */
    public static final short PRIVATE_CLASS = 3;

    // Tag data
    static short tag;
    static short tagClass;
    static boolean isPrimitive;

    // Offset and length for the value
    static short valueOffset;
    static short valueLength;

    private BERTLVScanner() { }

    public static short readTag(byte[] in, short offset) {
        short in_p = offset;
        short b = (short) (in[in_p] & 0xff);
        while (b == 0 || b == 0xff) {
            in_p++;
            b = in[in_p]; /* skip 00 and FF */
        }
        switch (b & 0xC0) {
        case 0:
            tagClass = UNIVERSAL_CLASS;
            break;
        case 0x40:
            tagClass = APPLICATION_CLASS;
            break;
        case 0x80:
            tagClass = CONTEXT_SPECIFIC_CLASS;
            break;
        case 0xC0:
            tagClass = PRIVATE_CLASS;
            break;
        }
        switch (b & 0x20) {
        case 0:
            isPrimitive = true;
            break;
        case 0x20:
            isPrimitive = false;
            break;
        }
        switch (b & 0x1F) {
        case 0x1F:
            tag = b;
            in_p++;
            b = in[in_p];
            while ((b & 0x80) == 0x80) {
                tag <<= 8;
                tag |= (b & 0x7F);
                in_p++;
                b = in[in_p];
            }
            tag <<= 8;
            tag |= (b & 0x7F);
            break;
        default:
            tag = b;
            break;
        }
        in_p++;
        return in_p;
    }

    public static short readLength(byte[] in, short offset) {
        short in_p = offset;
        short b = (short) (in[offset] & 0xff);
        if ((b & 0x80) == 0) {
            /* short form */
            valueLength = b;
        } else {
            /* long form */
            short count = (short) (b & 0x7F);
            valueLength = 0;
            for (short i = 0; i < count; i++) {
                in_p++;
                b = (short) (in[in_p] & 0xff);
                valueLength <<= 8;
                valueLength += b;
            }
        }
	   valueOffset = (short) (in_p + 1);
       return valueOffset;
    }

    public static short skipValue() {
        return (short) (valueOffset + valueLength);
    }

}
