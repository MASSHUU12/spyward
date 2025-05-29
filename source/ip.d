module ip;

class IpHeader
{
    ubyte ver;
    ubyte ihl;
    ubyte tos;
    ushort len;
    ushort flags;
    ushort fragOffset;
    ubyte ttl;
    ubyte protocol;
    ushort checksum;
    uint sourceAddress;
    uint destinationAddress;

    this(ubyte[20] buffer) pure
    {
        ver = (buffer[0] >> 4) & 0xF;
        ihl = buffer[0] & 0x0F;
        tos = buffer[1];
        len = (buffer[2] << 8 | buffer[3]);
        flags = (buffer[4] << 8 | buffer[5]);
        fragOffset = (buffer[6] << 8 | buffer[7]);
        ttl = buffer[8];
        protocol = buffer[9];
        checksum = (buffer[10] << 8 | buffer[11]);
        sourceAddress = (buffer[12] << 24 | buffer[13] << 16 | buffer[14] << 8 | buffer[15]);
        destinationAddress = (
            buffer[16] << 24 | buffer[17] << 16 | buffer[18] << 8 | buffer[19]);
    }
}
