package com.github.lukaszbudnik.keycloak.ipauthenticator;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SubnetUtils {
    private static final String IP_ADDRESS = "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})";
    private static final String SLASH_FORMAT = "(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,2})";
    private static final Pattern addressPattern = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    private static final Pattern cidrPattern = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,2})");
    private static final int NBITS = 32;
    private static final String PARSE_FAIL = "Could not parse [%s]";
    private final int netmask;
    private final int address;
    private final int network;
    private final int broadcast;
    private boolean inclusiveHostCount = false;

    public SubnetUtils(String cidrNotation) {
        Matcher matcher = cidrPattern.matcher(cidrNotation);
        if (matcher.matches()) {
            this.address = matchAddress(matcher);
            int trailingZeroes = 32 - rangeCheck(Integer.parseInt(matcher.group(5)), 0, 32);
            this.netmask = (int)(4294967295L << trailingZeroes);
            this.network = this.address & this.netmask;
            this.broadcast = this.network | ~this.netmask;
        } else {
            throw new IllegalArgumentException(String.format("Could not parse [%s]", cidrNotation));
        }
    }

    public SubnetUtils(String address, String mask) {
        this.address = toInteger(address);
        this.netmask = toInteger(mask);
        if ((this.netmask & -this.netmask) - 1 != ~this.netmask) {
            throw new IllegalArgumentException(String.format("Could not parse [%s]", mask));
        } else {
            this.network = this.address & this.netmask;
            this.broadcast = this.network | ~this.netmask;
        }
    }

    public boolean isInclusiveHostCount() {
        return this.inclusiveHostCount;
    }

    public void setInclusiveHostCount(boolean inclusiveHostCount) {
        this.inclusiveHostCount = inclusiveHostCount;
    }

    public final SubnetInfo getInfo() {
        return new SubnetInfo();
    }

    private static int toInteger(String address) {
        Matcher matcher = addressPattern.matcher(address);
        if (matcher.matches()) {
            return matchAddress(matcher);
        } else {
            throw new IllegalArgumentException(String.format("Could not parse [%s]", address));
        }
    }

    private static int matchAddress(Matcher matcher) {
        int addr = 0;

        for(int i = 1; i <= 4; ++i) {
            int n = rangeCheck(Integer.parseInt(matcher.group(i)), 0, 255);
            addr |= (n & 255) << 8 * (4 - i);
        }

        return addr;
    }

    private static int rangeCheck(int value, int begin, int end) {
        if (value >= begin && value <= end) {
            return value;
        } else {
            throw new IllegalArgumentException("Value [" + value + "] not in range [" + begin + "," + end + "]");
        }
    }

    int pop(int x) {
        x -= x >>> 1 & 1431655765;
        x = (x & 858993459) + (x >>> 2 & 858993459);
        x = x + (x >>> 4) & 252645135;
        x += x >>> 8;
        x += x >>> 16;
        return x & 63;
    }

    public SubnetUtils getNext() {
        return new SubnetUtils(this.getInfo().getNextAddress(), this.getInfo().getNetmask());
    }

    public SubnetUtils getPrevious() {
        return new SubnetUtils(this.getInfo().getPreviousAddress(), this.getInfo().getNetmask());
    }

    public final class SubnetInfo {
        private static final long UNSIGNED_INT_MASK = 4294967295L;

        private SubnetInfo() {
        }

        private long networkLong() {
            return (long)SubnetUtils.this.network & 4294967295L;
        }

        private long broadcastLong() {
            return (long)SubnetUtils.this.broadcast & 4294967295L;
        }

        private int low() {
            return SubnetUtils.this.isInclusiveHostCount() ? SubnetUtils.this.network : (this.broadcastLong() - this.networkLong() > 1L ? SubnetUtils.this.network + 1 : 0);
        }

        private int high() {
            return SubnetUtils.this.isInclusiveHostCount() ? SubnetUtils.this.broadcast : (this.broadcastLong() - this.networkLong() > 1L ? SubnetUtils.this.broadcast - 1 : 0);
        }

        public boolean isInRange(String address) {
            return this.isInRange(SubnetUtils.toInteger(address));
        }

        public boolean isInRange(int address) {
            if (address == 0) {
                return false;
            } else {
                long addLong = (long)address & 4294967295L;
                long lowLong = (long)this.low() & 4294967295L;
                long highLong = (long)this.high() & 4294967295L;
                return addLong >= lowLong && addLong <= highLong;
            }
        }

        public String getBroadcastAddress() {
            return this.format(this.toArray(SubnetUtils.this.broadcast));
        }

        public String getNetworkAddress() {
            return this.format(this.toArray(SubnetUtils.this.network));
        }

        public String getNetmask() {
            return this.format(this.toArray(SubnetUtils.this.netmask));
        }

        public String getAddress() {
            return this.format(this.toArray(SubnetUtils.this.address));
        }

        public String getNextAddress() {
            return this.format(this.toArray(SubnetUtils.this.address + 1));
        }

        public String getPreviousAddress() {
            return this.format(this.toArray(SubnetUtils.this.address - 1));
        }

        public String getLowAddress() {
            return this.format(this.toArray(this.low()));
        }

        public String getHighAddress() {
            return this.format(this.toArray(this.high()));
        }

        /** @deprecated */
        @Deprecated
        public int getAddressCount() {
            long countLong = this.getAddressCountLong();
            if (countLong > 2147483647L) {
                throw new RuntimeException("Count is larger than an integer: " + countLong);
            } else {
                return (int)countLong;
            }
        }

        public long getAddressCountLong() {
            long b = this.broadcastLong();
            long n = this.networkLong();
            long count = b - n + (long)(SubnetUtils.this.isInclusiveHostCount() ? 1 : -1);
            return count < 0L ? 0L : count;
        }

        public int asInteger(String address) {
            return SubnetUtils.toInteger(address);
        }

        public String getCidrSignature() {
            return this.format(this.toArray(SubnetUtils.this.address)) + "/" + SubnetUtils.this.pop(SubnetUtils.this.netmask);
        }

        public String[] getAllAddresses() {
            int ct = this.getAddressCount();
            String[] addresses = new String[ct];
            if (ct == 0) {
                return addresses;
            } else {
                int add = this.low();

                for(int j = 0; add <= this.high(); ++j) {
                    addresses[j] = this.format(this.toArray(add));
                    ++add;
                }

                return addresses;
            }
        }

        private int[] toArray(int val) {
            int[] ret = new int[4];

            for(int j = 3; j >= 0; --j) {
                ret[j] |= val >>> 8 * (3 - j) & 255;
            }

            return ret;
        }

        private String format(int[] octets) {
            StringBuilder str = new StringBuilder();

            for(int i = 0; i < octets.length; ++i) {
                str.append(octets[i]);
                if (i != octets.length - 1) {
                    str.append(".");
                }
            }

            return str.toString();
        }

    public String toString() {
            StringBuilder buf = new StringBuilder();
            buf.append("CIDR Signature:\t[").append(this.getCidrSignature()).append("]").append(" Netmask: [").append(this.getNetmask()).append("]\n").append("Network:\t[").append(this.getNetworkAddress()).append("]\n").append("Broadcast:\t[").append(this.getBroadcastAddress()).append("]\n").append("First Address:\t[").append(this.getLowAddress()).append("]\n").append("Last Address:\t[").append(this.getHighAddress()).append("]\n").append("# Addresses:\t[").append(this.getAddressCount()).append("]\n");
            return buf.toString();
        }
    }
}