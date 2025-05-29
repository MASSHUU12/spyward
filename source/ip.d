module ip;

/// Common interface for both v4 and v6 headers
interface IIPHeader
{
    /// dotted-decimal or canonical IPv6 representation
    string sourceAsString() const pure;
    string destinationAsString() const pure;
}

IIPHeader parseIPHeader(const(ubyte[]) buf) pure
{
    auto ver = (buf[0] >> 4) & 0xF;
    if (ver == 4)
    {
        // Copy into a fixed buffer before constructing
        ubyte[20] tmp4;
        tmp4[] = buf[0 .. 20];
        return new IP4Header(tmp4);
    }
    else if (ver == 6)
    {
        ubyte[40] tmp6;
        tmp6[] = buf[0 .. 40];
        return new IP6Header(tmp6);
    }
    assert(0, "Unsupported IP version");
}

void logIPHeader(const(IIPHeader) hdr)
{
    import std.stdio;

    if (auto i = cast(IP4Header) hdr)
    {
        writefln("IPv%d header:", i.ver);
        writeln("\tTTL: ", i.ttl);
        writeln("\tTotal Length: ", i.totalLength);
    }
    else if (auto i = cast(IP6Header) hdr)
    {
        writefln("IPv%d header:", i.ver);
        writeln("\tHop limit: ", i.hopLimit);
        writeln("\tPayload length: ", i.payloadLength);
    }

    writeln("\tFrom: ", hdr.sourceAsString());
    writeln("\tTo: ", hdr.destinationAsString());
}

class IP4Header : IIPHeader
{
    ubyte ver; // Version (4 bits)
    ubyte ihl; // Internet Header Length (4 bits)
    ubyte typeOfService; // Type of Service (8 bits)
    ushort totalLength; // Total Length (16 bits)
    ushort identification; // Identification (16 bits)
    ubyte flags; // Flags (3 bits)
    ushort fragmentOffset; // Fragment Offset (13 bits)
    ubyte ttl; // Time To Live (8 bits)
    ubyte protocol; // Protocol (8 bits)
    ushort headerChecksum; // Header Checksum (16 bits)
    uint sourceAddress; // Source Address (32 bits)
    uint destinationAddress; // Destination Address (32 bits)

    this(ubyte[20] buffer) pure
    {
        ver = (buffer[0] >> 4) & 0xF;
        ihl = buffer[0] & 0x0F;
        typeOfService = buffer[1];
        totalLength = cast(ushort)((cast(ushort) buffer[2] << 8) | buffer[3]);
        identification = cast(ushort)((cast(ushort) buffer[4] << 8) | buffer[5]);
        flags = (buffer[6] >> 5) & 0x7;
        fragmentOffset = cast(ushort)(((buffer[6] & 0x1F) << 8) | buffer[7]);
        ttl = buffer[8];
        protocol = buffer[9];
        headerChecksum = cast(ushort)((cast(ushort) buffer[10] << 8) | buffer[11]);
        sourceAddress = cast(uint)(
            (cast(uint) buffer[12] << 24)
                | (cast(uint) buffer[13] << 16)
                | (
                    cast(uint) buffer[14] << 8)
                | buffer[15]
        );
        destinationAddress = cast(uint)(
            (cast(uint) buffer[16] << 24)
                | (cast(uint) buffer[17] << 16)
                | (
                    cast(uint) buffer[18] << 8)
                | buffer[19]
        );
    }

    private string ip4ToString(uint addr) const pure
    {
        import std.format : format;

        return format("%d.%d.%d.%d",
            (addr >> 24) & 0xFF,
            (addr >> 16) & 0xFF,
            (addr >> 8) & 0xFF,
            addr & 0xFF
        );
    }

    override string sourceAsString() const pure
    {
        return ip4ToString(sourceAddress);
    }

    override string destinationAsString() const pure
    {
        return ip4ToString(destinationAddress);
    }
}

class IP6Header : IIPHeader
{
    ubyte ver; // Version (4 bits)
    ubyte trafficClass; // Traffic Class (8 bits: 4 from [0], 4 from [1])
    uint flowLabel; // Flow Label (20 bits)
    ushort payloadLength; // Payload Length (16 bits)
    ubyte nextHeader; // Next Header (8 bits)
    ubyte hopLimit; // Hop Limit (8 bits)
    ubyte[16] sourceAddress; // Source Address (128 bits)
    ubyte[16] destinationAddress; // Destination Address (128 bits)

    this(ubyte[40] buffer) pure
    {
        ver = (buffer[0] >> 4) & 0xF;
        trafficClass = cast(ubyte)((cast(ubyte)(buffer[0] & 0x0F) << 4)
                | ((buffer[1] >> 4) & 0xF));
        flowLabel = cast(uint)(
            (cast(uint)(buffer[1] & 0x0F) << 16)
                | (cast(uint) buffer[2] << 8)
                | buffer[3]
        );
        payloadLength = cast(ushort)((cast(ushort) buffer[4] << 8) | buffer[5]);
        nextHeader = buffer[6];
        hopLimit = buffer[7];
        sourceAddress[] = buffer[8 .. 24];
        destinationAddress[] = buffer[24 .. 40];
    }

    private string ip6ToString(const(ubyte)[16] addr) const pure
    {
        import std.format : format;
        import std.string : join, replace;

        string[] parts;
        parts.length = 8;
        foreach (i; 0 .. 8)
        {
            ushort val = cast(ushort)(addr[i * 2] << 8) | addr[i * 2 + 1];
            parts[i] = format("%x", val);
        }

        // Find longest run of "0" parts
        size_t bestStart = 0, bestLen = 0;
        size_t curStart = 0, curLen = 0;
        foreach (i, p; parts)
        {
            if (p == "0")
            {
                if (curLen == 0)
                    curStart = i;
                curLen++;
                if (curLen > bestLen)
                {
                    bestStart = curStart;
                    bestLen = curLen;
                }
            }
            else
            {
                curLen = 0;
            }
        }

        // Compress if run >= 2
        if (bestLen > 1)
        {
            parts = parts[0 .. bestStart]
                ~ [""]
                ~ parts[bestStart + bestLen .. $];
        }

        auto joined = parts.join(":");
        // Guard against accidental ":::" sequences
        return replace(joined, ":::", "::");
    }

    override string sourceAsString() const pure
    {
        return ip6ToString(sourceAddress);
    }

    override string destinationAsString() const pure
    {
        return ip6ToString(destinationAddress);
    }
}
