package io.github.barteks2x.bigmc64;

public class TestExample {

    public static void test(int x, int y, int z, int value) {
        for (int dx = -1; dx <= 1; dx++) {
            for (int dy = -1; dy <= 1; dy++) {
                for (int dz = -1; dz <= 1; dz++) {
                    for (int i = 0; i < value; i++) {
                        int xx = x+dx;
                        int yy = y+dy*value;
                        int zz = z+dz;
                        System.out.printf("HELLO %d %d %d\n", xx, yy, zz);
                    }
                }
            }
        }
    }

    public static void testBackwards(int x, int y, int z) {
        for (int i = 0; i < 10; i++) {
            test(x, y, z, i);
        }
    }
}
