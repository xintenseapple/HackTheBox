import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class UpTheStream {

    public static void main(String[] var0) {
        try {
            File inputFile = new File("output.txt");
            Scanner inputScanner = new Scanner(inputFile);

            if (!inputScanner.hasNextLine()) {
                System.out.println("Invalid input file.");
                System.exit(1);
            }

            String data = inputScanner.nextLine();
            System.out.println("Flag: " + dryTheFlag(data));
        } catch (FileNotFoundException e) {
            System.out.println("Input file 'output.txt' not found.");
            System.exit(1);
        }
    }

    private static String dryTheFlag(String s) {

        if (s.length() % 5 != 0) {
            System.out.println("Input cannot be correct...");
            System.exit(1);
        }

        return Arrays.stream(s.substring(0, s.length() / 5).split("O"))
                .map(c -> Integer.parseInt(c, 16))
                .map(UpTheStream::concentrate)
                .peek(UpTheStream::desiccate)
                .map(UpTheStream::dry)
                .map(UpTheStream::parch)
                .collect(Collector.of(
                        StringBuilder::new,
                        StringBuilder::appendCodePoint,
                        StringBuilder::append,
                        StringBuilder::reverse))
                .toString();
    }

    private static List<String> dunkTheFlag(String s) {
        return List.of(s.chars().mapToObj((var0x) -> (char) var0x)
                .collect(Collectors.toList()).stream()
                .peek(UpTheStream::hydrate)
                .map(Object::toString)
                .reduce("", (var0x, var1) -> var1 + var0x)
                .chars().mapToObj((var0x) -> (char) var0x)
                .collect(Collectors.toList()).stream()
                .map(Object::toString)
                .reduce(String::concat)
                .get().chars().boxed()
                .collect(Collectors.toList()).stream()
                .map(UpTheStream::moisten)
                .map(UpTheStream::drench)
                .peek(UpTheStream::waterlog)
                .map(UpTheStream::dilute)
                .map(Integer::toHexString)
                .reduce("", (var0x, var1) -> var0x + var1 + "O")
                .repeat(5));
    }

    private static Integer hydrate(Character var0) {
        return var0 - 1;
    }

    private static Character dehydrate(Integer c) {
        return (char) (c + 1);
    }

    private static Integer moisten(int var0) {
        return (int) (var0 % 2 == 0 ? (double) var0 : Math.pow(var0, 2.0));
    }

    private static int parch(Integer i) {
        return (int) (i % 2 == 0 ? i : Math.sqrt(i));
    }

    private static Integer drench(Integer var0) {
        return var0 << 1;
    }

    // NOTE: We forever lose data here. However, it is irrelevant
    //       because it is never actually applied.
    private static Integer dry(Integer i) {
        return i >> 1;
    }

    private static Integer dilute(Integer var0) {
        return var0 / 2 + var0;
    }

    private static Integer concentrate(Integer i) {
        return (i * 2) / 3;
    }

    private static byte waterlog(Integer var0) {
        var0 = ((var0 + 2) * 4 % 87 ^ 3) == 17362 ? var0 * 2 : var0 / 2;
        return var0.byteValue();
    }

    private static Integer desiccate(Integer b) {
        // Average best guess!
        return b * 2;
    }
}
