import sys
import re
import struct
import base64
import zipfile
import tarfile
import StringIO
import itertools

'''
Post-processing for ASCII art generated via
https://manytools.org/hacker-tools/convert-images-to-ascii-art

Steps:
1. Generate art
2. Get html code, save it to file
3. Copy ASCII art, save as text file, patch background holes if needed
4. Run this script
'''

ONE_SYMBOL = re.compile(r'<span style="color:rgb\((\d+)\s*,\s*(\d+)\s*,\s*(\d+)\);">(.)</span>')

def parse(fname):
    symbols = []
    with open(fname) as inp:
        for line in inp:
            current = []
            for r, g, b, sym in ONE_SYMBOL.findall(line.strip()):
                # converting taken from here:
                # https://stackoverflow.com/questions/4842424/list-of-ansi-color-escape-sequences
                r, g, b = [(int(x) * 5) / 255 for x in (r, g, b)]
                current.append((16 + 36 * r + 6 * g + b, sym))
            if current:
                symbols.append(current)
    return symbols

def patch_background(symbols, fname):
    background = symbols[-1][-1]
    with open(fname) as inp:
        for line_idx, line in enumerate(inp):
            for sym_idx, sym in enumerate(line.strip()):
                try:
                    if symbols[line_idx][sym_idx][1] != sym:
                        symbols[line_idx][sym_idx] = background
                except IndexError:
                    raise ValueError('%s patch not matching ASCII art in size' % fname)
    return symbols

def compact(symbols):
    result = []
    for line in symbols:
        row, current_color, current_symbols = [], None, ''
        for color, symbol in line:
            if color == current_color:
                current_symbols += symbol
            else:
                if current_color is not None:
                    row.append((current_color, current_symbols))
                current_color, current_symbols = color, symbol
        if current_color is not None:
            row.append((current_color, current_symbols))
        result.append(row)
    return result

def pack(symbols):
    result = []
    for line in symbols:
        row = []
        for color, text in line:
            if text.count(text[0]) == len(text):
                size, text = -len(text), text[0]
            else:
                size = len(text)
            row.append(struct.pack('<Bb%ds' % len(text), color, size, text))
        result.append(''.join(row))
    return '\n'.join(result)
    
def encode(data, fname, use_zip=True):
    buf = StringIO.StringIO()
    if use_zip:
        with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('ascii-ansi.bin', data)
        with open(fname + '.zip', 'wb') as out:
            out.write(buf.getvalue())
    else:
        data_buf = StringIO.StringIO(data)
        with tarfile.open(fname + '.tgz', 'w:bz2', buf) as tf:
            entry = tarfile.TarInfo('ascii-ansi.bin')
            entry.size = len(data)
            tf.addfile(entry, data_buf)
        with open(fname + '.tbz2', 'wb') as out:
            out.write(buf.getvalue())

    encoded = base64.b64encode(buf.getvalue())
    with open(fname, 'wb') as out:
        out.write('zip\n' if use_zip else 'tar\n')
        for group in itertools.izip_longest(*[iter(encoded)] * 120, fillvalue=''):
            out.write(''.join(group) + '\n')

if __name__ == '__main__':
    try:
        in_fname, text_fname, out_fname = sys.argv[1:]
    except ValueError:
        sys.exit('Usage: %s input.html patched.txt output-esc.zip.b64' % sys.argv[0])
    parsed = parse(in_fname)
    patched = patch_background(parsed, text_fname)
    compacted = compact(patched)
    packed = pack(compacted)
    encode(packed, out_fname, use_zip=False)
