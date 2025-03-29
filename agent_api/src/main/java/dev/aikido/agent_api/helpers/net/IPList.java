package dev.aikido.agent_api.helpers.net;

import gnu.trove.set.hash.TIntHashSet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;

public final class IPList {    
    private final TIntHashSet ipv4Singles;
    private final IPV6Array ipv6Singles;

    private final int[] ipv4Prefixes;
    private final byte[] ipv4MaskBits;

    private final IPV6Array ipv6Prefixes;
    private final byte[] ipv6MaskBits;

    public IPList(
        Iterable<String> ips
    ) {
        var ipv4Singles = new TIntHashSet();
        var ipv4Ranges = new ArrayList<int[]>();
        var ipv6Singles = new ArrayList<IPV6Array.IPv6Address>();
        var ipv6Ranges = new ArrayList<long[]>();

        for (var ip : ips) {
            if (ip.contains("/")) {
                var parts = ip.split("/");
                if (parts.length != 2) {
                    throw new IllegalArgumentException("Invalid CIDR notation: " + ip);
                }
                int maskBits = Integer.parseInt(parts[1]);
                
                if (maskBits > 32) {
                    throw new IllegalArgumentException("Invalid mask bits: " + maskBits);
                }
                
                if (ip.contains(":")) {
                    var addr = parseIPv6(parts[0]);
                    ipv6Ranges.add(new long[]{addr.highBits(), addr.lowBits(), maskBits});
                } else {
                    ipv4Ranges.add(new int[]{ipv4ToInt(parts[0]), maskBits});
                }
            } else {
                if (ip.contains(":")) {
                    ipv6Singles.add(parseIPv6(ip));
                } else {
                    ipv4Singles.add(ipv4ToInt(ip));
                }
            }
        }

        this.ipv4Singles = ipv4Singles;
        this.ipv6Singles = new IPV6Array(ipv6Singles);

        // Sort and convert the IPv4 ranges to parallel arrays
        int rangeCount = ipv4Ranges.size();
        this.ipv4Prefixes = new int[rangeCount];
        this.ipv4MaskBits = new byte[rangeCount];
        
        ipv4Ranges.sort((a, b) -> Integer.compare(a[0], b[0]));
        for (int i = 0; i < rangeCount; i++) {
            int[] range = ipv4Ranges.get(i);
            ipv4Prefixes[i] = range[0];
            ipv4MaskBits[i] = (byte) range[1];
        }


        // Sort and convert IPv6 ranges to parallel arrays
        ipv6Ranges.sort((a, b) -> {
            long highCompare = Long.compare(a[0], b[0]);
            return highCompare != 0 ? Long.compare(a[0], b[0]) : Long.compare(a[1], b[1]);
        });
        int ipv6RangeCount = ipv6Ranges.size();
        this.ipv6MaskBits = new byte[ipv6RangeCount];
        for (int i = 0; i < ipv6RangeCount; i++) {
            long[] range = ipv6Ranges.get(i);
            ipv6MaskBits[i] = (byte) range[2];
        }
        this.ipv6Prefixes = new IPV6Array(ipv6Ranges.stream().map(r -> new IPV6Array.IPv6Address(r[0], r[1])).collect(Collectors.toList()));
    }

    private static int readInt(byte[] bytes, int offset) {
        return ((bytes[offset] & 0xFF) << 24) |
               ((bytes[offset + 1] & 0xFF) << 16) |
               ((bytes[offset + 2] & 0xFF) << 8) |
               (bytes[offset + 3] & 0xFF);
    }

    private static long readLong(byte[] bytes, int offset) {
        return ((long) bytes[offset]     << 56) |
               ((long) (bytes[offset + 1] & 0xFF) << 48) |
               ((long) (bytes[offset + 2] & 0xFF) << 40) |
               ((long) (bytes[offset + 3] & 0xFF) << 32) |
               ((long) (bytes[offset + 4] & 0xFF) << 24) |
               ((long) (bytes[offset + 5] & 0xFF) << 16) |
               ((long) (bytes[offset + 6] & 0xFF) << 8) |
               ((long) (bytes[offset + 7] & 0xFF));
    }
    
    public static int ipv4ToInt(String ipv4) {
        try {
            byte[] bytes = InetAddress.getByName(ipv4).getAddress();
            return readInt(bytes, 0);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv4 address: " + ipv4, e);
        }
    }

    public static IPV6Array.IPv6Address parseIPv6(String ipv6) {
        try {
            InetAddress addr = InetAddress.getByName(ipv6);
            byte[] bytes = addr.getAddress();
            
            long highBits = readLong(bytes, 0);
            long lowBits = readLong(bytes, 8);
            
            return new IPV6Array.IPv6Address(highBits, lowBits);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Invalid IPv6 address: " + ipv6, e);
        }
    }

    public boolean matches(String ip) {
        if (ip == null) return false;
        
        if (ip.contains(":")) {
            return matchesIPv6(ip);
        } else {
            return matchesIPv4(ip);
        }
    }

    private boolean matchesIPv4(String ip) {
        int ipInt = ipv4ToInt(ip);
        
        // Check single IPs first
        if (ipv4Singles.contains(ipInt)) {
            return true;
        }
        
        // Binary search for potential match
        int idx = Arrays.binarySearch(ipv4Prefixes, ipInt);
        if (idx >= 0) {
            return true;  // Exact match always means it's in the range
        }
        
        // Get insertion point
        int insertionPoint = -(idx + 1);
        if (insertionPoint == 0) {
            return false;  // No ranges before insertion point
        }
        
        // Check the range before insertion point
        int prevIdx = insertionPoint - 1;
        int mask = -1 << (32 - (ipv4MaskBits[prevIdx] & 0xFF));
        return (ipInt & mask) == ipv4Prefixes[prevIdx];
    }

    private boolean matchesIPv6(String ip) {
        IPV6Array.IPv6Address addr = parseIPv6(ip);

        // Check single IPs first
        if (ipv6Singles.binarySearch(addr) >= 0) {
            return true;
        }
        
        // Binary search for potential match
        int idx = ipv6Prefixes.binarySearch(addr);
        if (idx >= 0) {
            return true;  // Exact match
        }
        
        // Get insertion point and check previous range
        int insertionPoint = -(idx + 1);
        if (insertionPoint == 0) {
            return false;
        }
        
        // Check the range before insertion point
        int prevIdx = insertionPoint - 1;
        int maskBits = ipv6MaskBits[prevIdx] & 0xFF;
        long prefixHighBits = ipv6Prefixes.getHighBits(prevIdx);
        
        if (maskBits <= 64) {
            long mask = -1L << (64 - maskBits);
            return (addr.highBits() & mask) == prefixHighBits;
        } else {
            if (addr.highBits() != prefixHighBits) {
                return false;
            }
            long mask = -1L << (128 - maskBits);
            long prefixLowBits = ipv6Prefixes.getLowBits(prevIdx);
            return (addr.lowBits() & mask) == prefixLowBits;
        }
    }
}
