import re
import base64
import codecs

def extract_ascii_strings(data, min_length=4):
    """
    Extract ASCII strings from binary data.
    """
    pattern = re.compile(b'[\x20-\x7E]{' + str(min_length).encode() + b',}')
    return pattern.findall(data)

def decode_base64_strings(strings):
    """
    Attempt to decode base64-encoded strings.
    """
    decoded_strings = []
    for s in strings:
        try:
            decoded_string = base64.b64decode(s).decode('utf-8')
            decoded_strings.append(decoded_string)
        except (base64.binascii.Error, UnicodeDecodeError):
            continue
    return decoded_strings

def decode_hex_strings(strings):
    """
    Attempt to decode hex-encoded strings.
    """
    decoded_strings = []
    for s in strings:
        try:
            decoded_string = bytes.fromhex(s).decode('utf-8')
            decoded_strings.append(decoded_string)
        except (ValueError, UnicodeDecodeError):
            continue
    return decoded_strings

def decode_rot13_strings(strings):
    """
    Attempt to decode rot13-encoded strings.
    """
    decoded_strings = [codecs.decode(s, 'rot_13') for s in strings]
    return decoded_strings

def find_stack_strings(data):
    """
    Heuristic to find stack strings in the binary data.
    """
    stack_strings = []
    # Heuristic: looking for PUSH instructions followed by printable characters
    pattern = re.compile(b'\x68([\x20-\x7E]{4})')
    matches = pattern.findall(data)
    for match in matches:
        stack_strings.append(match.decode('utf-8'))
    return stack_strings

def find_tight_strings(data, min_length=4):
    """
    Heuristic to find tight strings in the binary data.
    """
    tight_strings = []
    pattern = re.compile(b'([\x00-\x7F]{' + str(min_length).encode() + b',})')
    matches = pattern.findall(data)
    for match in matches:
        try:
            tight_string = match.decode('utf-8')
            if len(tight_string) >= min_length:
                tight_strings.append(tight_string)
        except UnicodeDecodeError:
            continue
    return tight_strings

def analyze_binary(file_path):
    """
    Analyze the binary file to extract and decode strings.
    """
    with open(file_path, 'rb') as f:
        data = f.read()

    # Extract ASCII strings
    ascii_strings = extract_ascii_strings(data)
    ascii_strings = [s.decode('utf-8') for s in ascii_strings]

    # Decode base64-encoded strings
    base64_strings = decode_base64_strings(ascii_strings)

    # Decode hex-encoded strings
    hex_strings = decode_hex_strings(ascii_strings)

    # Decode rot13-encoded strings
    rot13_strings = decode_rot13_strings(ascii_strings)

    # Find stack strings
    stack_strings = find_stack_strings(data)

    # Find tight strings
    tight_strings = find_tight_strings(data)

    return {
        'ascii_strings': ascii_strings,
        'base64_strings': base64_strings,
        'hex_strings': hex_strings,
        'rot13_strings': rot13_strings,
        'stack_strings': stack_strings,
        'tight_strings': tight_strings
    }

def main():
    binary_path = 'path/to/your/binary'  # Replace with the path to your binary file
    results = analyze_binary(binary_path)

    print("ASCII Strings:")
    for s in results['ascii_strings']:
        print(s)

    print("\nBase64 Decoded Strings:")
    for s in results['base64_strings']:
        print(s)

    print("\nHex Decoded Strings:")
    for s in results['hex_strings']:
        print(s)

    print("\nRot13 Decoded Strings:")
    for s in results['rot13_strings']:
        print(s)

    print("\nStack Strings:")
    for s in results['stack_strings']:
        print(s)

    print("\nTight Strings:")
    for s in results['tight_strings']:
        print(s)

if __name__ == '__main__':
    main()
