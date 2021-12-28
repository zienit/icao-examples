package nl.zienit.icao_examples;

import org.junit.Test;

import java.util.stream.Stream;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

/**
 * Unit tests demonstrating:
 * ICAO
 * Doc 9303
 * Machine Readable Travel Documents
 * Eighth Edition, 2021
 * Part 3: Specifications Common to all MRTDs
 * APPENDIX A TO PART 3 — EXAMPLES OF CHECK DIGIT CALCULATION (INFORMATIVE)
 */
public class CheckDigitTest {

    private int digitValue(byte digit) {
        return digit >= '0' && digit <= '9'
                ? digit - '0'
                : digit >= 'A' && digit <= 'Z'
                ? digit - 'A' + 10
                : 0;
    }

    // section 4.9 Check Digits in the MRZ
    private int computeCheckDigit(byte[] digits, int off, int len) {

        final var weights = new int[]{7, 3, 1};

        return Stream.iterate(0, i -> i < len, i -> i + 1)
                .map(i -> weights[i % 3] * digitValue(digits[off + i]))
                .reduce(0, Integer::sum) % 10;
    }

    private int computeCheckDigit(String digits) {
        return computeCheckDigit(digits.getBytes(), 0, digits.length());
    }

    @Test
    public void testExample1() {
        assertThat(computeCheckDigit("520727"), equalTo(3));
    }

    @Test
    public void testExample2() {
        assertThat(computeCheckDigit("AB2134<<<"), equalTo(5));
    }

    @Test
    public void testExample3() {
        final var lower = "HA672242<6YTO5802254M9601086<<<<<<<<<<<<<<0";
        assertThat(computeCheckDigit(lower.substring(0, 10) + lower.substring(13, 20) + lower.substring(21, 43)), equalTo(8));
    }

    @Test
    public void testExample4() {
        final var upper = "I<YTOD231458907<<<<<<<<<<<<<<<";
        final var middle = "3407127M9507122YTO<<<<<<<<<<<";
        assertThat(computeCheckDigit(upper.substring(5, 30) + middle.substring(0, 7) + middle.substring(8, 15) + middle.substring(18, 29)), equalTo(2));
    }

    @Test
    public void testExample5() {
        final var lower = "HA672242<6YTO5802254M9601086<<<<<<<";
        assertThat(computeCheckDigit(lower.substring(0, 10) + lower.substring(13, 20) + lower.substring(21, 35)), equalTo(8));
    }
}
