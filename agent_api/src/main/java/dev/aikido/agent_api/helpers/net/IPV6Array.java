package dev.aikido.agent_api.helpers.net;

import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class IPV6Array {
    public record IPv6Address(long highBits, long lowBits) implements Comparable<IPv6Address> {
        @Override
        public int compareTo(IPv6Address other) {
            int highCompare = Long.compare(this.highBits, other.highBits);
            return highCompare != 0 ? highCompare : Long.compare(this.lowBits, other.lowBits);
        }
    }

    private final long[] ipv6Array;

    public IPV6Array(Iterable<IPv6Address> ipv6Array) {
        this.ipv6Array = StreamSupport.stream(ipv6Array.spliterator(), false)
            .sorted()
            .flatMap(i -> Stream.of(i.highBits, i.lowBits))
            .mapToLong(Long::longValue)
            .toArray();
    }

    public IPv6Address get(int index) {
        return new IPv6Address(ipv6Array[index * 2], ipv6Array[index * 2 + 1]);
    }
    public long getHighBits(int index) {
        return ipv6Array[index * 2];
    }
    public long getLowBits(int index) {
        return ipv6Array[index * 2 + 1];
    }

    public int binarySearch(IPv6Address ipv6Address) {
        return binarySearch(ipv6Address.highBits(), ipv6Address.lowBits());
    }

    public int binarySearch(long highBits, long lowBits) {
        int lowIdx = 0;
        int highIdx = ipv6Array.length / 2 - 1;
        int closestSmallerIdx = -1;

        while (lowIdx <= highIdx) {
            int midIdx = lowIdx + (highIdx - lowIdx) / 2;
            long midValHighBits = ipv6Array[midIdx * 2];
            long midValLowBits = ipv6Array[midIdx * 2 + 1];
            if (midValHighBits < highBits || (midValHighBits == highBits && midValLowBits < lowBits)) {
                closestSmallerIdx = midIdx;
                lowIdx = midIdx + 1;
            } else if (midValHighBits > highBits || (midValHighBits == highBits && midValLowBits > lowBits)) {
                highIdx = midIdx - 1;
            } else {
                return midIdx;
            }
        }

        return -closestSmallerIdx - 1;
    }
}
