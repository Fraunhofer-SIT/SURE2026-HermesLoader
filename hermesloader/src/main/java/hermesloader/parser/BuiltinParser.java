package hermesloader.parser;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for Hermes builtin definitions.
 * Parses the Builtins.def file and provides access to builtin methods by index.
 */
public class BuiltinParser {
    private static final Pattern BUILTIN_METHOD_PATTERN =
        Pattern.compile("BUILTIN_METHOD\\s*\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*\\)");
    private static final Pattern PRIVATE_BUILTIN_PATTERN =
        Pattern.compile("PRIVATE_BUILTIN\\s*\\(\\s*(\\w+)\\s*\\)");

    private final List<String> builtinMethods;
    private final Map<Integer, String> indexToMethod;
    private final Map<String, Integer> methodToIndex;

    public BuiltinParser() throws IOException {
        this.builtinMethods = new ArrayList<>();
        this.indexToMethod = new HashMap<>();
        this.methodToIndex = new HashMap<>();
        // Use relative path from the parser's location
        String content = Files.readString(Paths.get("hermes_defs/Builtins.def"));
        parseBuiltinsDef(content);
    }

    public BuiltinParser(String builtinsDefContent) {
        this.builtinMethods = new ArrayList<>();
        this.indexToMethod = new HashMap<>();
        this.methodToIndex = new HashMap<>();
        parseBuiltinsDef(builtinsDefContent);
    }

    private void parseBuiltinsDef(String content) {
        // Split content into lines and filter out comments and empty lines
        String[] lines = content.split("\\r?\\n");

        int index = 0;
        for (String line : lines) {
            // Skip comments and empty lines
            String trimmedLine = line.trim();
            if (trimmedLine.startsWith("//") || trimmedLine.startsWith("#") ||
                trimmedLine.isEmpty() ||
                (!trimmedLine.contains("BUILTIN_METHOD") && !trimmedLine.contains("PRIVATE_BUILTIN"))) {
                continue;
            }

            Matcher methodMatcher = BUILTIN_METHOD_PATTERN.matcher(trimmedLine);
            Matcher privateMatcher = PRIVATE_BUILTIN_PATTERN.matcher(trimmedLine);

            if (methodMatcher.find()) {
                String object = methodMatcher.group(1);
                String method = methodMatcher.group(2);
                String fullMethodName = object + "." + method;

                builtinMethods.add(fullMethodName);
                indexToMethod.put(index, fullMethodName);
                methodToIndex.put(fullMethodName, index);
                index++;
            } else if (privateMatcher.find()) {
                String method = privateMatcher.group(1);
                // Private builtins don't have an object prefix, so we'll use "HermesInternal" as the object
                String fullMethodName = "HermesInternal." + method;

                builtinMethods.add(fullMethodName);
                indexToMethod.put(index, fullMethodName);
                methodToIndex.put(fullMethodName, index);
                index++;
            }
        }
    }

    /**
     * Get builtin method name by index.
     * @param hexIndex Index in hexadecimal format (e.g., "0xa3")
     * @return The builtin method name at the specified index
     * @throws IllegalArgumentException if index is invalid or out of bounds
     */
    public String getBuiltinByIndex(String hexIndex) {
        int index = parseHexIndex(hexIndex);
        return getBuiltinByIndex(index);
    }

    /**
     * Get builtin method name by decimal index.
     * @param index Decimal index
     * @return The builtin method name at the specified index
     * @throws IllegalArgumentException if index is out of bounds
     */
    public String getBuiltinByIndex(int index) {
        if (index < 0 || index >= builtinMethods.size()) {
            throw new IllegalArgumentException("Index out of bounds: " + index +
                " (valid range: 0x00 to 0x" + Integer.toHexString(builtinMethods.size() - 1) + ")");
        }
        return indexToMethod.get(index);
    }

    /**
     * Get the index of a builtin method.
     * @param methodName The method name in format "Object.method"
     * @return The index of the method
     * @throws IllegalArgumentException if method is not found
     */
    public int getIndexByMethod(String methodName) {
        Integer index = methodToIndex.get(methodName);
        if (index == null) {
            throw new IllegalArgumentException("Method not found: " + methodName);
        }
        return index;
    }

    /**
     * Get all builtin methods as an ordered list.
     * @return List of all builtin method names
     */
    public List<String> getAllBuiltins() {
        return new ArrayList<>(builtinMethods);
    }

    /**
     * Get the total number of builtin methods.
     * @return Total count of builtin methods
     */
    public int getBuiltinCount() {
        return builtinMethods.size();
    }

    private int parseHexIndex(String hexIndex) {
        if (hexIndex.startsWith("0x") || hexIndex.startsWith("0X")) {
            try {
                return Integer.parseInt(hexIndex.substring(2), 16);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid hexadecimal index: " + hexIndex);
            }
        } 
        throw new IllegalArgumentException("Index must be in hexadecimal format (e.g., 0xa3): " + hexIndex);
    }

    /**
     * Main method for testing the parser with the actual Builtins.def file.
     */
    public static void main(String[] args) {
        try {
            BuiltinParser parser = new BuiltinParser();

            System.out.println("Total builtins: " + parser.getBuiltinCount());
            System.out.println();

            // Show builtin methods
            System.out.println("builtin methods:");
            for (int i = 0; i < parser.getBuiltinCount(); i++) {
                System.out.printf("0x%02X: %s%n", i, parser.getBuiltinByIndex(i));
            }
            System.out.println();

        } catch (IOException e) {
            System.err.println("Error reading Builtins.def file: " + e.getMessage());
            System.exit(1);
        } catch (RuntimeException e) {
            System.err.println("Error: " + e.getMessage());
            System.exit(1);
        }
    }
}
