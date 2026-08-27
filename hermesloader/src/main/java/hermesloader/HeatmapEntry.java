package hermesloader;

public class HeatmapEntry {
    public final String fieldName;
    public final String objectName;
    public final String opcode;

    public HeatmapEntry(String fieldName, String objectName, String opcode) {
        this.fieldName = fieldName;
        this.objectName = objectName;
        this.opcode = opcode;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HeatmapEntry that = (HeatmapEntry) o;
        return java.util.Objects.equals(fieldName, that.fieldName) && java.util.Objects.equals(objectName, that.objectName) && java.util.Objects.equals(opcode, that.opcode);
    }

    @Override
    public int hashCode() {
        return java.util.Objects.hash(fieldName, objectName, opcode);
    }

    @Override
    public String toString() {
        return "[fieldName='" + fieldName + "', objectName='" + objectName + "', opcode='" + opcode + "']";
    }
}
