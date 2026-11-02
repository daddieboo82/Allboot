import struct, zlib, math, os
W=64; H=64
rows=[]
for y in range(H):
    row=bytearray([0])
    for x in range(W):
        # Deep navy tile with a cyan rounded border and a simple white boot-chevron motif.
        edge=min(x,y,W-1-x,H-1-y)
        r,g,b,a=10,24,42,255
        if edge <= 3:
            r,g,b=27,185,222
        # stylized A: two diagonal strokes and crossbar
        in_a = (abs(y - (0.95*(x-15)+14)) <= 3 and 14<=x<=32 and 13<=y<=48) or (abs(y - (-0.95*(x-32)+48)) <= 3 and 27<=x<=49 and 13<=y<=48)
        cross = 28<=y<=33 and 22<=x<=42
        if in_a or cross: r,g,b=232,246,255
        # tiny cyan boot arrow at lower right
        if 42<=x<=52 and 43<=y<=51 and (x-42) >= abs(y-47): r,g,b=65,220,210
        row.extend((r,g,b,a))
    rows.append(bytes(row))
raw=b''.join(rows)
def chunk(kind,data):
    return struct.pack(">I",len(data))+kind+data+struct.pack(">I",zlib.crc32(kind+data)&0xffffffff)
png=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack(">2I5B",W,H,8,6,0,0,0))+chunk(b'IDAT',zlib.compress(raw,9))+chunk(b'IEND',b'')
ico_header=struct.pack("<HHH",0,1,1)
entry=struct.pack("<BBBBHHII",W,H,0,0,1,32,len(png),22)
out=os.path.join(os.path.dirname(__file__),"icon.ico")
open(out,"wb").write(ico_header+entry+png)
print("WROTE",out,"bytes",os.path.getsize(out))
