package hermesloader.structs;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

import ghidra.util.Msg;

public final class HermesSourcesDataStruct {

    private static final Pattern NON_HEX = Pattern.compile("[^0-9A-Fa-f]");

    public static final class ParseException extends RuntimeException {
        public ParseException(String msg) { super(msg); }
    }

    public record SourcePoint(
            int address,
            int line,
            int column,
            int statement,
            int scopeAddress,
            int envReg) {}

    public record FunctionSourceInfo(
            int functionIndex,
            int startLine,
            int startColumn,
            List<SourcePoint> points) {}

    private static final class Cursor {
        final byte[] data;
        int off;
        Cursor(byte[] data) { this.data = data; }
        boolean eof() { return off >= data.length; }
    }

    /**
     * Decode a signed LEB128 value and advance cursor.
     * Returns long (then range-checked) to make shift math safe.
     */
    private static long readSLEB128(Cursor c) {
        long result = 0;
        int shift = 0;
        int byteCount = 0;
        while (true) {
            if (c.off >= c.data.length) {
                throw new ParseException("Unexpected EOF in SLEB128");
            }
            int b = c.data[c.off++] & 0xFF;
            byteCount++;
            result |= (long)(b & 0x7F) << shift;
            boolean cont = (b & 0x80) != 0;
            shift += 7;
            if (!cont) {
                // Sign bit of last payload byte
                if (shift < 64 && (b & 0x40) != 0) {
                    result |= -1L << shift;
                }
                break;
            }
            if (byteCount > 10) {
                throw new ParseException("SLEB128 too long (corrupt?)");
            }
        }
        return result;
    }

    private static int readSLEB128AsInt(Cursor c) {
        long v = readSLEB128(c);
        // Accept non-canonical SLEB encodings that still fit in 32 bits. Some Hermes
        // debug streams emit values like 0xFFFFFFFF (encoded in multiple bytes) which
        // our generic decoder interprets as unsigned 4294967295 instead of sign-extended -1
        // because the final continuation byte did not set the sign bit. If the value fits
        // inside 32 bits when viewed as an unsigned quantity, reinterpret its lower 32 bits
        // as a signed two's complement int.
        if ((v & ~0xFFFFFFFFL) == 0) {
            return (int)(v & 0xFFFFFFFFL);
        }
        if (v < Integer.MIN_VALUE || v > Integer.MAX_VALUE) {
            throw new ParseException("Value out of 32-bit range: " + v);
        }
        return (int) v;
    }

    /**
     * Parse entire buffer into list of function debug records.
     * Stops when input exhausted or a structural error is encountered.
     */
    public static List<FunctionSourceInfo> parse(byte[] sourcesData) {
        return parse(sourcesData, false);
    }

    /**
     * Parse entire buffer into list of function debug records.
     * Layout (concatenated for all functions):
     *   functionIndex (SLEB128)
     *   startLine     (SLEB128, 1-based)
     *   startColumn   (SLEB128, 1-based)
     *   repeated location entries until terminator:
     *     addressDelta  (SLEB128)  -- if -1, terminates this function's block
     *     lineDeltaRaw  (SLEB128)  -- low bit encodes presence of statementDelta
     *     columnDelta   (SLEB128)
     *     scopeAddress  (SLEB128)
     *     envReg        (SLEB128)
     *     [statementDelta] (SLEB128, only if (lineDeltaRaw & 1) != 0)
     *   Decoding lineDeltaRaw:
     *     hasStatement = (lineDeltaRaw & 1) != 0
     *     lineDelta    = arithmeticRightShift(lineDeltaRaw, 1)
     * All deltas are applied cumulatively. Statement numbers start at 0 for
     * the function start (enforced by generator) and only change when a
     * statementDelta field is present.
     */
    public static List<FunctionSourceInfo> parse(byte[] sourcesData, boolean debug) {
        Objects.requireNonNull(sourcesData, "sourcesData");
        Cursor cur = new Cursor(sourcesData);
        List<FunctionSourceInfo> out = new ArrayList<>();

        while (!cur.eof()) {
            int functionIndex = readSLEB128AsInt(cur);
            int startLine = readSLEB128AsInt(cur);
            int startColumn = readSLEB128AsInt(cur);

            if (startLine < 1 || startColumn < 1) {
                throw new ParseException("Lines/columns must be 1-based. Got line=" +
                        startLine + " col=" + startColumn +
                        " at byte offset " + (cur.off));
            }

            int address = 0;
            int line = startLine;
            int column = startColumn;
            int statement = 0;
            List<SourcePoint> points = new ArrayList<>();

            while (true) {
                int peek;
                // Need to look ahead without consuming permanently
                int saved = cur.off;
                try {
                    peek = readSLEB128AsInt(cur);
                } catch (ParseException e) {
                    throw new ParseException("Reading adelta failed @offset=" + saved + ": " + e.getMessage());
                }

                if (peek == -1) {
                    // End of function. (We consumed the terminator already.)
                    break;
                }

                int adelta = peek;
                int ldeltaPacked = readSLEB128AsInt(cur);
                int cdelta = readSLEB128AsInt(cur);
                int scopeAddress = readSLEB128AsInt(cur);
                int envReg = readSLEB128AsInt(cur);

                // Arithmetic shift to preserve sign of line delta (Java's >> is arithmetic).
                int lineDelta = ldeltaPacked >> 1;
                boolean hasStatement = (ldeltaPacked & 1) != 0;
                int sdelta = 0;
                if (hasStatement) {
                    sdelta = readSLEB128AsInt(cur);
                }

                address += adelta;
                line += lineDelta;
                column += cdelta;
                statement += sdelta; // Only changes if present (else sdelta==0)

                if (address < 0) {
                    throw new ParseException("Negative cumulative address at offset " + cur.off);
                }
                if (line < 1 || column < 1) {
                    throw new ParseException("Decoded line/column must remain 1-based. line=" + line + " col=" + column);
                }

                points.add(new SourcePoint(address, line, column, statement, scopeAddress, envReg));

                if (debug) {                    
                    // Lightweight on-demand debug logging per added point.
                    Msg.debug(HermesSourcesDataStruct.class, "[hermes-sources] f=" + functionIndex +
                            " addr=" + address + " line=" + line + " col=" + column +
                            " stmt=" + statement + " scope=" + scopeAddress + " envReg=" + envReg);
                }
            }

            out.add(new FunctionSourceInfo(functionIndex, startLine, startColumn, points));
            if (debug) {
                Msg.debug(HermesSourcesDataStruct.class,
                        "[hermes-sources] end function #" + functionIndex + " points=" + points.size());
            }
        }

        return out;
    }

    /**
     * Utility: convert a string of hex bytes (with or without spaces) to raw bytes.
     */
    public static byte[] hexToBytes(String hex) {
        hex = NON_HEX.matcher(hex).replaceAll("");
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Odd hex length");
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream(hex.length() / 2);
        for (int i = 0; i < hex.length(); i += 2) {
            bos.write(Integer.parseInt(hex.substring(i, i + 2), 16));
        }
        return bos.toByteArray();
    }

    /**
     * Pretty print for quick inspection.
     */
    public static String describe(List<FunctionSourceInfo> infos) {
        StringBuilder sb = new StringBuilder();
        for (FunctionSourceInfo f : infos) {
            sb.append("Function #").append(f.functionIndex())
              .append(" start (line=").append(f.startLine())
              .append(", col=").append(f.startColumn()).append(")\n");
            for (SourcePoint p : f.points()) {
                sb.append("  addr=").append(p.address())
                  .append(" line=").append(p.line())
                  .append(" col=").append(p.column())
                  .append(" stmt=").append(p.statement())
                  .append(" scope=").append(p.scopeAddress())
                  .append(" envReg=").append(p.envReg())
                  .append("\n");
            }
        }
        return sb.toString();
    }
}
